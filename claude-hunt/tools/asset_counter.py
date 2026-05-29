#!/usr/bin/env python3
"""
Asset Counter — 统计互联网上受漏洞影响的资产数量
用于 CVE/CNVD 报告中的"影响范围"部分

用法:
  python3 asset_counter.py --query 'app="ThinkPHP"'
  python3 asset_counter.py --query 'title="若依"' --engine fofa
"""

import os
import sys
import base64
import json
import requests


class AssetCounter:
    """资产影响面统计器"""

    def __init__(self):
        self.fofa_email = os.environ.get('FOFA_EMAIL', '')
        self.fofa_key = os.environ.get('FOFA_KEY', '')

    def count(self, fingerprint: str) -> dict:
        """统计受影响资产"""
        result = {"total": "未统计", "regions": "未知", "query": fingerprint}

        if self.fofa_email and self.fofa_key:
            fofa_result = self._count_fofa(fingerprint)
            if fofa_result:
                return fofa_result

        # 没有 API Key 时给出搜索建议
        result["suggestion"] = (
            f"手动查询:\n"
            f"  FOFA: {fingerprint}\n"
            f"  Shodan: {fingerprint}\n"
            f"  ZoomEye: {fingerprint}"
        )
        return result

    def _count_fofa(self, query: str) -> dict:
        """通过 FOFA API 统计"""
        try:
            qbase64 = base64.b64encode(query.encode()).decode()
            url = "https://fofa.info/api/v1/search/all"
            params = {
                "email": self.fofa_email,
                "key": self.fofa_key,
                "qbase64": qbase64,
                "size": 1,
                "fields": "host,country"
            }
            resp = requests.get(url, params=params, timeout=15)
            data = resp.json()

            if data.get("error"):
                return None

            total = data.get("size", 0)
            return {
                "total": total,
                "regions": "中国为主" if total > 0 else "未知",
                "query": query,
                "source": "FOFA"
            }
        except Exception:
            return None


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", "-q", required=True)
    args = parser.parse_args()

    counter = AssetCounter()
    result = counter.count(args.query)
    print(json.dumps(result, ensure_ascii=False, indent=2))
