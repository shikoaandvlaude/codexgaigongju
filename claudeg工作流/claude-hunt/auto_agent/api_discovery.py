#!/usr/bin/env python3
"""
API Discovery — API Schema 自动发现模块
从多种来源自动发现和解析 API 端点

发现来源：
1. Swagger/OpenAPI (swagger.json, openapi.json, /api-docs)
2. GraphQL Introspection (__schema)
3. WADL / WSDL (XML-based API 描述)
4. 常见 API 路径探测 (/api/v1/, /v2/, etc.)
5. robots.txt / sitemap.xml 中的 API 路径
6. HTML/JS 中提取的端点

用法:
    discovery = APIDiscovery(http_engine)
    endpoints = await discovery.discover("https://target.com")
"""

import asyncio
import json
import re
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class APIEndpoint:
    """发现的 API 端点"""
    method: str = "GET"
    path: str = ""
    full_url: str = ""
    params: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    body_schema: dict = field(default_factory=dict)
    auth_required: bool = False
    description: str = ""
    source: str = ""  # swagger/graphql/probe/robots/js


@dataclass
class APIDiscoveryResult:
    """发现结果"""
    endpoints: list = field(default_factory=list)
    graphql_types: list = field(default_factory=list)
    graphql_mutations: list = field(default_factory=list)
    graphql_queries: list = field(default_factory=list)
    swagger_info: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)


class APIDiscovery:
    """API 自动发现"""

    def __init__(self, http_engine, config: dict = None):
        self.http = http_engine
        self.config = config or {}
        self.cookies = self.config.get("cookies", {})
        self.headers = self.config.get("headers", {})

    async def discover(self, base_url: str) -> APIDiscoveryResult:
        """执行完整的 API 发现"""
        result = APIDiscoveryResult()

        # 1. 探测 Swagger/OpenAPI
        swagger = await self._discover_swagger(base_url)
        result.endpoints.extend(swagger)

        # 2. 探测 GraphQL
        graphql = await self._discover_graphql(base_url)
        result.endpoints.extend(graphql.get("endpoints", []))
        result.graphql_types = graphql.get("types", [])
        result.graphql_mutations = graphql.get("mutations", [])
        result.graphql_queries = graphql.get("queries", [])

        # 3. 常见 API 路径探测
        probed = await self._probe_common_paths(base_url)
        result.endpoints.extend(probed)

        # 4. robots.txt / sitemap
        robot_endpoints = await self._parse_robots_sitemap(base_url)
        result.endpoints.extend(robot_endpoints)

        # 去重
        seen = set()
        unique = []
        for ep in result.endpoints:
            key = f"{ep.method}|{ep.path}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        result.endpoints = unique

        return result

    # ─── Swagger/OpenAPI ───────────────────────────────────────

    async def _discover_swagger(self, base_url: str) -> list[APIEndpoint]:
        """探测和解析 Swagger/OpenAPI"""
        endpoints = []

        swagger_paths = [
            "/swagger.json", "/openapi.json", "/api-docs",
            "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
            "/api/swagger.json", "/api/openapi.json",
            "/swagger/v1/swagger.json",  # ASP.NET
            "/api-docs/swagger.json",
            "/docs/openapi.json",
            "/_swagger", "/swagger-ui.html",
            "/swagger-resources",
        ]

        for path in swagger_paths:
            url = urljoin(base_url, path)
            resp = await self.http.request("GET", url, cookies=self.cookies, headers=self.headers)

            if resp.status_code == 200 and resp.body:
                try:
                    spec = json.loads(resp.body)
                    if "paths" in spec or "openapi" in spec or "swagger" in spec:
                        parsed = self._parse_openapi_spec(spec, base_url)
                        endpoints.extend(parsed)
                        break  # 找到一个就够了
                except json.JSONDecodeError:
                    pass

        return endpoints

    def _parse_openapi_spec(self, spec: dict, base_url: str) -> list[APIEndpoint]:
        """解析 OpenAPI/Swagger spec"""
        endpoints = []
        paths = spec.get("paths", {})
        base_path = spec.get("basePath", "")

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    full_path = base_path + path
                    params = []

                    # 提取参数
                    for param in details.get("parameters", []):
                        params.append({
                            "name": param.get("name", ""),
                            "in": param.get("in", ""),
                            "required": param.get("required", False),
                            "type": param.get("type", param.get("schema", {}).get("type", "")),
                        })

                    endpoints.append(APIEndpoint(
                        method=method.upper(),
                        path=full_path,
                        full_url=urljoin(base_url, full_path),
                        params=params,
                        auth_required=bool(details.get("security")),
                        description=details.get("summary", details.get("description", "")),
                        source="swagger",
                    ))

        return endpoints

    # ─── GraphQL ──────────────────────────────────────────────

    async def _discover_graphql(self, base_url: str) -> dict:
        """探测和解析 GraphQL schema"""
        result = {"endpoints": [], "types": [], "mutations": [], "queries": []}

        graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/query"]

        for path in graphql_paths:
            url = urljoin(base_url, path)

            # Introspection 查询
            introspection_query = {
                "query": """{ __schema { queryType { name } mutationType { name }
                    types { name kind fields { name type { name kind ofType { name } }
                    args { name type { name } } } } } }"""
            }

            resp = await self.http.request(
                "POST", url,
                json_data=introspection_query,
                headers={**self.headers, "Content-Type": "application/json"},
                cookies=self.cookies,
            )

            if resp.status_code == 200 and "__schema" in resp.body:
                try:
                    data = json.loads(resp.body)
                    schema = data.get("data", {}).get("__schema", {})

                    # 提取 types
                    for type_info in schema.get("types", []):
                        name = type_info.get("name", "")
                        if name.startswith("__"):
                            continue

                        result["types"].append(name)

                        # 每个 field 都是潜在的查询端点
                        for field_info in (type_info.get("fields") or []):
                            field_name = field_info.get("name", "")
                            args = field_info.get("args", [])

                            if type_info.get("name") == schema.get("queryType", {}).get("name"):
                                result["queries"].append({
                                    "name": field_name,
                                    "args": [{"name": a["name"], "type": a.get("type", {}).get("name", "")} for a in args],
                                })
                            elif type_info.get("name") == schema.get("mutationType", {}).get("name"):
                                result["mutations"].append({
                                    "name": field_name,
                                    "args": [{"name": a["name"], "type": a.get("type", {}).get("name", "")} for a in args],
                                })

                    # 为每个 mutation 创建端点
                    for mutation in result["mutations"]:
                        result["endpoints"].append(APIEndpoint(
                            method="POST",
                            path=path,
                            full_url=url,
                            params=[{"name": a["name"], "type": a["type"]} for a in mutation["args"]],
                            description=f"GraphQL Mutation: {mutation['name']}",
                            source="graphql",
                        ))

                    # GraphQL 端点本身
                    result["endpoints"].append(APIEndpoint(
                        method="POST",
                        path=path,
                        full_url=url,
                        description="GraphQL endpoint (introspection enabled)",
                        source="graphql",
                    ))

                    break  # 找到一个就够了

                except (json.JSONDecodeError, KeyError):
                    pass

        return result

    # ─── 路径探测 ──────────────────────────────────────────────

    async def _probe_common_paths(self, base_url: str) -> list[APIEndpoint]:
        """探测常见 API 路径"""
        endpoints = []

        common_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/rest", "/rest/v1", "/rest/v2",
            "/api/health", "/api/status", "/api/info",
            "/api/users", "/api/user", "/api/me",
            "/api/auth/login", "/api/auth/register",
            "/api/config", "/api/settings",
            "/actuator", "/actuator/env", "/actuator/health",
            "/debug", "/debug/vars", "/debug/pprof",
            "/.well-known/openid-configuration",
            "/oauth/token", "/oauth/authorize",
            "/api/upload", "/api/files", "/api/export",
            "/api/admin", "/api/internal",
            "/wp-json/wp/v2/users",  # WordPress
            "/api/v1/metadata",
        ]

        for path in common_paths:
            url = urljoin(base_url, path)
            resp = await self.http.request("GET", url, cookies=self.cookies, headers=self.headers)

            if resp.status_code in (200, 201, 401, 403, 405):
                endpoints.append(APIEndpoint(
                    method="GET",
                    path=path,
                    full_url=url,
                    auth_required=(resp.status_code in (401, 403)),
                    description=f"探测到活跃端点 (HTTP {resp.status_code})",
                    source="probe",
                ))

        return endpoints

    # ─── robots.txt / sitemap ─────────────────────────────────

    async def _parse_robots_sitemap(self, base_url: str) -> list[APIEndpoint]:
        """从 robots.txt 和 sitemap.xml 中提取"""
        endpoints = []

        # robots.txt
        robots_url = urljoin(base_url, "/robots.txt")
        resp = await self.http.request("GET", robots_url)
        if resp.status_code == 200 and resp.body:
            for line in resp.body.split("\n"):
                line = line.strip()
                if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and "/api" in path.lower() or "/admin" in path.lower():
                        endpoints.append(APIEndpoint(
                            method="GET",
                            path=path,
                            full_url=urljoin(base_url, path),
                            description=f"Found in robots.txt",
                            source="robots",
                        ))

        # sitemap.xml
        sitemap_url = urljoin(base_url, "/sitemap.xml")
        resp = await self.http.request("GET", sitemap_url)
        if resp.status_code == 200 and resp.body:
            urls_in_sitemap = re.findall(r'<loc>([^<]+)</loc>', resp.body)
            for url in urls_in_sitemap:
                if "/api/" in url or "/v1/" in url or "/v2/" in url:
                    parsed = urlparse(url)
                    endpoints.append(APIEndpoint(
                        method="GET",
                        path=parsed.path,
                        full_url=url,
                        description="Found in sitemap.xml",
                        source="sitemap",
                    ))

        return endpoints

    def get_summary(self, result: APIDiscoveryResult) -> dict:
        """获取发现摘要"""
        return {
            "total_endpoints": len(result.endpoints),
            "by_source": {
                src: len([e for e in result.endpoints if e.source == src])
                for src in set(e.source for e in result.endpoints)
            },
            "by_method": {
                m: len([e for e in result.endpoints if e.method == m])
                for m in set(e.method for e in result.endpoints)
            },
            "auth_required": len([e for e in result.endpoints if e.auth_required]),
            "graphql_types": len(result.graphql_types),
            "graphql_mutations": len(result.graphql_mutations),
            "graphql_queries": len(result.graphql_queries),
        }
