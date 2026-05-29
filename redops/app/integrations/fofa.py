"""
RedOps Web - FOFA集成模块
"""

import requests
import base64
from typing import Dict, Any


class FOFAClient:
    def __init__(self, email: str = None, key: str = None):
        self.email = email or ""
        self.key = key or ""
        self.base_url = "https://fofa.info/api/v1"
    
    def search(self, query: str, size: int = 100, page: int = 1) -> Dict[str, Any]:
        qbase64 = base64.b64encode(query.encode()).decode()
        url = f"{self.base_url}/search/all"
        params = {"qbase64": qbase64, "size": size, "page": page, "fields": "host,title,ip,port,server"}
        if self.email and self.key:
            params["email"] = self.email
            params["key"] = self.key
        try:
            response = requests.get(url, params=params, timeout=30)
            data = response.json()
            results = []
            for item in data.get("results", []):
                results.append({"host": item[0], "title": item[1], "ip": item[2], "port": item[3], "server": item[4]})
            return {"size": len(results), "results": results, "query": query}
        except Exception as e:
            return {"error": str(e)}


FOFA_QUERIES = {
    "登录页面": 'title="登录" || title="login"',
    "后台": 'title="管理" || title="admin"',
    "摄像头": 'protocol="rtsp"',
    "数据库": 'protocol="mysql" || protocol="postgresql"',
    "Redis": 'protocol="redis"',
    "Elasticsearch": 'protocol="elasticsearch"',
    "Jenkins": 'product="Jenkins"',
    "Spring": 'framework="spring"',
}


def build_query(keyword: str, **kwargs) -> str:
    return f'("{keyword}")'
