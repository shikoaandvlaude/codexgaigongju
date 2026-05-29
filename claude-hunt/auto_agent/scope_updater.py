"""
Scope Updater - SRC 授权范围自动更新模块
定期检查/更新 SRC 平台的授权测试范围，防止测试已下架目标
"""

import os
import json
import fnmatch
from datetime import datetime, timedelta
from typing import Optional


class ScopeUpdater:
    """SRC 授权范围管理器"""

    def __init__(self, config: dict):
        self.config = config
        self.scope_config = config.get('scope_updater', {})
        self.enabled = self.scope_config.get('enabled', True)
        self.max_age_hours = self.scope_config.get('max_age_hours', 24)
        self.data_dir = os.path.expanduser(
            self.scope_config.get('data_dir', '~/.bai-agent/scope')
        )
        # 自动创建目录
        os.makedirs(self.data_dir, exist_ok=True)

    def load_scope(self, platform_name: str) -> Optional[dict]:
        """加载指定平台的 scope 数据"""
        filepath = os.path.join(self.data_dir, f"{platform_name}.json")
        if not os.path.exists(filepath):
            return None
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None

    def update_scope(self, platform_name: str, domains: list, out_of_scope: list, source: str = 'manual'):
        """写入/覆盖 scope 文件，记录当前时间戳"""
        filepath = os.path.join(self.data_dir, f"{platform_name}.json")
        data = {
            "domains": domains,
            "out_of_scope": out_of_scope,
            "last_updated": datetime.now().isoformat(),
            "source": source
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def check_freshness(self, platform_name: str = None) -> bool:
        """
        检查 scope 数据是否在 max_age_hours 内
        如果未指定 platform_name，检查所有平台
        返回 True 表示数据新鲜，False 表示过期
        """
        if platform_name:
            data = self.load_scope(platform_name)
            if data is None:
                return False
            return self._is_fresh(data.get('last_updated'))
        
        # 检查所有 scope 文件
        if not os.path.exists(self.data_dir):
            return True  # 没有数据文件时不报警
        
        json_files = [f for f in os.listdir(self.data_dir) if f.endswith('.json')]
        if not json_files:
            return True  # 没有数据文件时不报警
        
        for filename in json_files:
            filepath = os.path.join(self.data_dir, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if not self._is_fresh(data.get('last_updated')):
                    return False
            except (json.JSONDecodeError, IOError):
                continue
        
        return True

    def _is_fresh(self, last_updated_str: str) -> bool:
        """判断时间戳是否在 max_age_hours 以内"""
        if not last_updated_str:
            return False
        try:
            last_updated = datetime.fromisoformat(last_updated_str)
            return datetime.now() - last_updated < timedelta(hours=self.max_age_hours)
        except (ValueError, TypeError):
            return False

    def warn_if_stale(self):
        """如果 scope 数据过期，打印 Rich 警告"""
        if not self.enabled:
            return
        
        stale_platforms = []
        if not os.path.exists(self.data_dir):
            return
        
        json_files = [f for f in os.listdir(self.data_dir) if f.endswith('.json')]
        for filename in json_files:
            filepath = os.path.join(self.data_dir, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if not self._is_fresh(data.get('last_updated')):
                    platform = filename.replace('.json', '')
                    stale_platforms.append(platform)
            except (json.JSONDecodeError, IOError):
                continue
        
        if stale_platforms:
            try:
                from rich.console import Console
                c = Console()
                c.print(
                    f"[bold yellow]警告: 以下平台的 scope 数据已超过 "
                    f"{self.max_age_hours} 小时未更新: "
                    f"{', '.join(stale_platforms)}[/bold yellow]"
                )
                c.print("[yellow]建议使用 --scope-update 更新授权范围[/yellow]")
            except ImportError:
                print(
                    f"警告: 以下平台的 scope 数据已超过 "
                    f"{self.max_age_hours} 小时未更新: "
                    f"{', '.join(stale_platforms)}"
                )
                print("建议使用 --scope-update 更新授权范围")

    def is_target_in_scope(self, target: str, scope: list = None, out_of_scope: list = None) -> bool:
        """
        检查目标是否在授权范围内（使用 fnmatch 匹配）
        如果 scope 为 None/空，使用 config 中的 target.scope
        始终检查 target.out_of_scope
        """
        if scope is None:
            scope = self.config.get('target', {}).get('scope', [])
        if out_of_scope is None:
            out_of_scope = self.config.get('target', {}).get('out_of_scope', [])

        # 检查是否在 out_of_scope 中
        for pattern in out_of_scope:
            if fnmatch.fnmatch(target, pattern):
                return False

        # 检查是否在 scope 中
        if not scope:
            return True  # 没定义 scope 就默认允许

        for pattern in scope:
            if fnmatch.fnmatch(target, pattern):
                return True

        return False

    def get_merged_scope(self) -> tuple:
        """
        合并 config.yaml 中的 scope 与所有已加载的平台 scope 文件
        返回 (combined_scope_list, combined_out_of_scope_list)
        """
        combined_scope = list(self.config.get('target', {}).get('scope', []))
        combined_out_of_scope = list(self.config.get('target', {}).get('out_of_scope', []))

        if not os.path.exists(self.data_dir):
            return (combined_scope, combined_out_of_scope)

        json_files = [f for f in os.listdir(self.data_dir) if f.endswith('.json')]
        for filename in json_files:
            filepath = os.path.join(self.data_dir, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                # 合并 domains
                for domain in data.get('domains', []):
                    if domain not in combined_scope:
                        combined_scope.append(domain)
                # 合并 out_of_scope
                for oos in data.get('out_of_scope', []):
                    if oos not in combined_out_of_scope:
                        combined_out_of_scope.append(oos)
            except (json.JSONDecodeError, IOError):
                continue

        return (combined_scope, combined_out_of_scope)

    def update_from_file(self, filepath: str, platform_name: str = 'manual'):
        """
        从用户提供的文本文件导入 scope（每行一个域名）
        读取文件，解析域名，调用 update_scope
        """
        if not os.path.exists(filepath):
            try:
                from rich.console import Console
                Console().print(f"[red]错误: 文件不存在: {filepath}[/red]")
            except ImportError:
                print(f"错误: 文件不存在: {filepath}")
            return

        domains = []
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.append(line)

        if domains:
            self.update_scope(platform_name, domains, [], source='manual')
            try:
                from rich.console import Console
                Console().print(f"[green]已导入 {len(domains)} 个域名到平台 '{platform_name}'[/green]")
            except ImportError:
                print(f"已导入 {len(domains)} 个域名到平台 '{platform_name}'")
        else:
            try:
                from rich.console import Console
                Console().print("[yellow]文件中没有有效的域名[/yellow]")
            except ImportError:
                print("文件中没有有效的域名")
