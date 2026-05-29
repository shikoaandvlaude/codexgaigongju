"""
RedOps - 配置管理模块
统一管理系统配置，支持热重载
"""

import os
import yaml
import json
from typing import Dict, Any, Optional
from pathlib import Path


class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_path: str = None):
        # 默认配置路径
        if config_path is None:
            if os.name == 'nt':  # Windows
                config_path = os.path.join(os.environ.get('APPDATA', '.'), 'RedOps', 'config.yaml')
            else:  # Linux/Mac
                config_path = os.path.expanduser('~/.config/redops/config.yaml')
        
        self.config_path = config_path
        self._config: Dict[str, Any] = {}
        self._watchers: list = []
        
        # 确保配置目录存在
        config_dir = os.path.dirname(config_path)
        if config_dir and not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)
        
        # 加载配置
        self.load()
    
    def load(self):
        """加载配置文件"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    if self.config_path.endswith('.yaml') or self.config_path.endswith('.yml'):
                        self._config = yaml.safe_load(f) or {}
                    elif self.config_path.endswith('.json'):
                        self._config = json.load(f)
                    else:
                        # 默认尝试YAML
                        self._config = yaml.safe_load(f) or {}
            except Exception as e:
                print(f"加载配置失败: {e}")
                self._config = {}
        else:
            # 使用默认配置
            self._config = self.get_default_config()
            self.save()
    
    def save(self):
        """保存配置文件"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                if self.config_path.endswith('.json'):
                    json.dump(self._config, f, indent=2, ensure_ascii=False)
                else:
                    yaml.dump(self._config, f, allow_unicode=True, default_flow_style=False)
            return True
        except Exception as e:
            print(f"保存配置失败: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value
    
    def set(self, key: str, value: Any):
        """设置配置项"""
        keys = key.split('.')
        config = self._config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
    
    def get_all(self) -> Dict[str, Any]:
        """获取全部配置"""
        return self._config.copy()
    
    def update(self, data: Dict[str, Any]):
        """批量更新配置"""
        self._config.update(data)
    
    def get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            "llm": {
                "provider": "deepseek",
                "api_key": "",
                "base_url": "https://api.deepseek.com/v1",
                "model": "deepseek-chat",
                "temperature": 0.7,
                "max_tokens": 4096
            },
            "system": {
                "root_mode": True,
                "allowed_paths": [
                    "/home",
                    "/tmp",
                    "/opt",
                    "/var/www",
                    "C:\\Users",
                    "C:\\Temp"
                ],
                "auto_install": True,
                "command_timeout": 30
            },
            "telegram": {
                "enabled": False,
                "bot_token": "",
                "allowed_chats": [],
                "webhook_url": ""
            },
            "qq": {
                "enabled": False,
                "ws_url": "ws://127.0.0.1:6700",
                "access_token": "",
                "allowed_groups": [],
                "allowed_qqs": []
            },
            "web": {
                "host": "0.0.0.0",
                "port": 8000,
                "username": "admin",
                "password": "redops123"
            },
            "security": {
                "enable_panic_button": True,
                "log_all_commands": True,
                "max_daily_commands": 1000
            }
        }
    
    def reset_to_default(self):
        """重置为默认配置"""
        self._config = self.get_default_config()
        self.save()


# 全局配置实例
_config_manager: Optional[ConfigManager] = None


def get_config_manager() -> ConfigManager:
    """获取配置管理器实例"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def init_config_manager(config_path: str = None) -> ConfigManager:
    """初始化配置管理器"""
    global _config_manager
    _config_manager = ConfigManager(config_path)
    return _config_manager
