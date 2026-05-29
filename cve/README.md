# CVE 漏洞报告

本目录存放通过白盒审计发现的安全漏洞报告。

## 目标项目

| 项目 | Stars | 语言 | 描述 | 发现数 |
|------|-------|------|------|--------|
| [SonicJs](https://github.com/SonicJs-Org/sonicjs) | 1570 | TypeScript | Edge-native headless CMS for Cloudflare Workers | 4 |
| [Automad](https://github.com/marcantondahmen/automad) | 894 | PHP | Flat-file content management system | 1 |
| [Vrite](https://github.com/vriteio/vrite) | 1979 | TypeScript | Developer content platform | 1 |
| [MindSpore](https://github.com/mindspore-ai/mindspore) | 4200+ | C++/Python | AI 训练推理框架 (华为) | 4 |

## 发现列表

### SonicJs (4 vulnerabilities)

| 编号 | 严重性 | 标题 | 文件 |
|------|--------|------|------|
| SONIC-2025-001 | Critical (9.8) | 未认证 seed-admin 端点导致管理员接管 | [sonicjs-001-seed-admin-takeover.md](sonicjs-001-seed-admin-takeover.md) |
| SONIC-2025-002 | High (7.5) | Media Upload R2 Key 路径穿越 | [sonicjs-002-r2-path-traversal.md](sonicjs-002-r2-path-traversal.md) |
| SONIC-2025-003 | High (8.1) | JWT Fallback Secret 硬编码 | [sonicjs-003-jwt-hardcoded-secret.md](sonicjs-003-jwt-hardcoded-secret.md) |
| SONIC-2025-004 | Medium (6.1) | Media Upload MIME 验证绕过 + SVG XSS | [sonicjs-004-mime-bypass-svg-xss.md](sonicjs-004-mime-bypass-svg-xss.md) |

### Automad (1 vulnerability)

| 编号 | 严重性 | 标题 | 文件 |
|------|--------|------|------|
| AUTOMAD-2025-001 | High (7.2) | 认证后 SSRF via File Import | [automad-001-ssrf-file-import.md](automad-001-ssrf-file-import.md) |

### Vrite (1 vulnerability)

| 编号 | 严重性 | 标题 | 文件 |
|------|--------|------|------|
| VRITE-2025-001 | High (7.5) | 未认证 SSRF via Link Preview | [vrite-001-unauthenticated-ssrf.md](vrite-001-unauthenticated-ssrf.md) |

### MindSpore (4 vulnerabilities)

| 编号 | 严重性 | 标题 | 文件 |
|------|--------|------|------|
| MS-2025-001 | Critical (8.6) | MindIR External Data 路径穿越任意文件读取 | [mindspore-001-path-traversal-mindir.md](mindspore-001-path-traversal-mindir.md) |
| MS-2025-002 | High (7.1) | MindIR External Data Offset 堆越界读取 | [mindspore-002-heap-oob-read-offset.md](mindspore-002-heap-oob-read-offset.md) |
| MS-2025-003 | Medium (5.5) | MindIR Tensor 未初始化内存信息泄露 | [mindspore-003-uninit-memory-disclosure.md](mindspore-003-uninit-memory-disclosure.md) |
| MS-2025-004 | Medium (5.5) | Protobuf 解析无大小限制 OOM DoS | [mindspore-004-protobuf-oom-dos.md](mindspore-004-protobuf-oom-dos.md) |

## 已审计但未发现漏洞的项目

| 项目 | Stars | 语言 | 结论 |
|------|-------|------|------|
| [Strapi](https://github.com/strapi/strapi) | 72k | TypeScript | 成熟项目，攻击面已加固 |
| [Payload CMS](https://github.com/payloadcms/payload) | 42k | TypeScript | 完善的 checkFileRestrictions |
| [Ghost](https://github.com/TryGhost/Ghost) | 53k | JavaScript | DOMPurify + 严格白名单 |
| [Directus](https://github.com/directus/directus) | 35k | TypeScript | Rate limiter + lodash 已修复 |
| [Nodepress](https://github.com/surmon-china/nodepress) | 1520 | TypeScript | 代码质量极高，escapeRegExp + RBAC |

## 审计方法

1. 使用 Bai-codeagent 自动化工具发现候选目标（GitHub Search API）
2. 优先选择 Stars 500-3000 的小众活跃项目
3. 聚焦边缘攻击面：文件导入/预览、WebSocket、模板引擎、插件系统
4. 从 GitHub 拉取源码进行白盒审计
5. 人工验证每个发现，排除误报
6. 编写带完整复现步骤的报告

## 免责声明

所有漏洞均通过源码审计发现，未对任何在线实例进行攻击测试。报告仅用于负责任披露。
