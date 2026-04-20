import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    pass


class MicroPKIConfig:
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.data = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        default_config = {
            'pki': {
                'out_dir': './pki',
                'db_path': './pki/micropki.db',
                'certs_dir': './pki/certs',
                'private_dir': './pki/private',
                'crl_dir': './pki/crl',
                'csrs_dir': './pki/csrs'
            },
            'ca': {
                'default_key_type': 'rsa',
                'default_key_size': 4096,
                'default_validity_days': 3650,
                'intermediate_validity_days': 1825,
                'leaf_validity_days': 365,
                'default_pathlen': 0
            },
            'repository': {
                'host': '127.0.0.1',
                'port': 8080,
                'enable_cors': True,
                'cache_control_max_age': 604800
            },
            'ocsp': {
                'host': '127.0.0.1',
                'port': 8081,
                'cache_ttl': 60,
                'enabled': True
            },
            'logging': {
                'level': 'INFO',
                'format': 'json',
                'file': None
            }
        }

        if not self.config_path:
            return default_config

        config_file = Path(self.config_path)
        if not config_file.exists():
            logger.warning(f"Config file not found: {self.config_path}, using defaults")
            return default_config

        try:
            if config_file.suffix in ['.yaml', '.yml']:
                with open(config_file, 'r') as f:
                    user_config = yaml.safe_load(f)
            elif config_file.suffix == '.json':
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
            else:
                raise ConfigError(f"Unsupported config format: {config_file.suffix}")

            self._merge_config(default_config, user_config)
            logger.info(f"Loaded configuration from {self.config_path}")
            return default_config

        except Exception as e:
            logger.error(f"Failed to load config: {str(e)}")
            raise ConfigError(f"Cannot load configuration: {str(e)}")

    def _merge_config(self, default: Dict, user: Dict):
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_config(default[key], value)
            else:
                default[key] = value

    def get(self, key: str, default=None):
        keys = key.split('.')
        value = self.data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        return value if value is not None else default

    @property
    def out_dir(self) -> Path:
        return Path(self.get('pki.out_dir', './pki'))

    @property
    def db_path(self) -> Path:
        return Path(self.get('pki.db_path', './pki/micropki.db'))

    @property
    def certs_dir(self) -> Path:
        return Path(self.get('pki.certs_dir', './pki/certs'))

    @property
    def repo_host(self) -> str:
        return self.get('repository.host', '127.0.0.1')

    @property
    def repo_port(self) -> int:
        return self.get('repository.port', 8080)

    @property
    def ocsp_host(self) -> str:
        return self.get('ocsp.host', '127.0.0.1')

    @property
    def ocsp_port(self) -> int:
        return self.get('ocsp.port', 8081)

    @property
    def ocsp_cache_ttl(self) -> int:
        return self.get('ocsp.cache_ttl', 60)

    @property
    def ocsp_enabled(self) -> bool:
        return self.get('ocsp.enabled', True)