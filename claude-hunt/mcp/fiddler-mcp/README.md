# Fiddler MCP Server

让 Claude Code 能够自动分析 Fiddler 的抓包数据。

## 功能

- `fiddler_list_captures` — 列出最近的抓包文件
- `fiddler_parse_saz` — 解析 SAZ 文件中的所有请求/响应
- `fiddler_search_params` — 搜索包含指定参数的请求（找注入点）
- `fiddler_find_endpoints` — 提取所有 API 端点
- `fiddler_find_sensitive` — 搜索敏感信息泄露（Key、Token、验证码等）

## 配置

在 Claude Code 中添加 MCP Server：

```bash
claude mcp add fiddler python3 /path/to/fiddler-mcp/server.py
```

或编辑 `~/.claude/settings.json`：

```json
{
  "mcpServers": {
    "fiddler": {
      "command": "python3",
      "args": ["C:/path/to/Bai-codeagent/claude-hunt/mcp/fiddler-mcp/server.py"],
      "env": {
        "FIDDLER_EXPORT_DIR": "C:/Users/你的用户名/Documents/Fiddler2/Captures"
      }
    }
  }
}
```

## Fiddler 端配置

### 方法一：手动导出 SAZ

File → Save → All Sessions → 保存到 Captures 目录

### 方法二：自动保存（推荐）

Rules → Customize Rules，在 `OnBeforeResponse` 中加：

```csharp
static function OnBeforeResponse(oSession: Session) {
    // 自动保存到指定目录
    oSession.SaveResponse("C:\\Users\\你的用户名\\Documents\\Fiddler2\\Captures\\auto\\");
}
```

## 使用示例

配好之后在 Claude Code 里：

```
请分析我最近的 Fiddler 抓包，找出所有包含 price/amount/qty 参数的请求
```

Claude Code 会自动调用 fiddler_search_params 工具。
