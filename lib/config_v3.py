"""
配置管理模块 v3.0

基于标准 OpenSSH config 格式的配置加载器

新特性：
1. 从 ~/.ssh/config 加载配置
2. 支持别名（Host）
3. 元数据从注释中解析
4. 完全兼容 ProxyJump（跳板机）
5. 支持密码认证（从注释中读取）
"""

import os
import json
import re
import fnmatch
import shlex
from typing import Dict, Optional, List
from pathlib import Path

try:
    import paramiko
except ImportError:
    paramiko = None


class SSHConfigLoaderV3:
    """SSH Config 加载器 v3.0

    从标准 OpenSSH config 文件加载配置
    """

    def __init__(self, config_path: Optional[str] = None,
                 metadata_path: Optional[str] = None):
        """
        初始化加载器

        Args:
            config_path: SSH config 文件路径，默认 ~/.ssh/config
            metadata_path: 元数据文件路径，默认 ~/.ssh/config_metadata.json
        """
        if config_path is None:
            config_path = os.path.expanduser("~/.ssh/config")
        if metadata_path is None:
            metadata_path = os.path.expanduser("~/.ssh/config_metadata.json")

        self.config_path = config_path
        self.metadata_path = metadata_path

    def load_ssh_config(self, alias: str) -> dict:
        """
        从 SSH config 加载指定别名的配置

        Args:
            alias: 主机别名

        Returns:
            配置字典

        Raises:
            FileNotFoundError: 配置文件不存在
            ValueError: 别名不存在
        """
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"SSH config 文件不存在: {self.config_path}")

        # 显式 Host 别名优先使用大小写敏感解析，避免 x / X 这类别名被 paramiko 混淆
        exact_host_config = self._load_explicit_host_config(alias)
        if exact_host_config is not None:
            return exact_host_config

        if paramiko is None:
            raise ImportError("需要安装 paramiko 库: pip install paramiko")

        # 解析 SSH config
        ssh_config = paramiko.SSHConfig()
        with open(self.config_path, 'r', encoding='utf-8') as f:
            ssh_config.parse(f)

        # 获取配置
        try:
            host_config = ssh_config.lookup(alias)
        except Exception as e:
            raise ValueError(f"无法解析别名 '{alias}': {e}")

        # 检查是否真的找到了配置（paramiko 会返回默认值）
        if host_config.get('hostname') == alias and not self._alias_exists(alias):
            raise ValueError(f"别名 '{alias}' 不存在于 SSH config 中")

        return host_config

    def _load_explicit_host_config(self, alias: str) -> Optional[dict]:
        """按大小写敏感方式解析显式 Host 块，并合并 Host * 默认项"""
        if not self._alias_exists(alias):
            return None

        config: Dict[str, object] = {}
        saw_host_or_match = False
        active_block = True

        with open(self.config_path, 'r', encoding='utf-8') as handle:
            for raw_line in handle:
                stripped = raw_line.strip()

                if not stripped or stripped.startswith('#'):
                    continue

                lowered = stripped.lower()
                if lowered.startswith('match '):
                    saw_host_or_match = True
                    active_block = False
                    continue

                if lowered.startswith('host '):
                    saw_host_or_match = True
                    patterns = stripped[5:].strip().split()
                    active_block = self._host_patterns_match(alias, patterns)
                    continue

                if not active_block and saw_host_or_match:
                    continue

                parts = stripped.split(None, 1)
                if len(parts) != 2:
                    continue

                key, value = parts
                normalized_key = key.lower()

                if normalized_key == 'identityfile':
                    config.setdefault('identityfile', [])
                    if value not in config['identityfile']:
                        config['identityfile'].append(value)
                    continue

                if normalized_key not in config:
                    config[normalized_key] = value

        return config or None

    @staticmethod
    def _host_patterns_match(alias: str, patterns: List[str]) -> bool:
        """按 OpenSSH Host 规则进行大小写敏感匹配"""
        positive_match = False

        for pattern in patterns:
            is_negative = pattern.startswith('!')
            raw_pattern = pattern[1:] if is_negative else pattern
            matched = fnmatch.fnmatchcase(alias, raw_pattern)

            if is_negative and matched:
                return False
            if not is_negative and matched:
                positive_match = True

        return positive_match

    def _alias_exists(self, alias: str) -> bool:
        """检查别名是否存在于 SSH config 中"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('Host ') and not line.startswith('Host *'):
                        # 提取 Host 名称
                        import re
                        host_match = re.match(r'Host\s+(.+)', line)
                        if host_match and host_match.group(1).strip() == alias:
                            return True
            return False
        except Exception:
            return False

    def load_metadata(self, alias: str) -> dict:
        """
        从注释中加载元数据

        Args:
            alias: 主机别名

        Returns:
            元数据字典（包括密码）
        """
        metadata = {
            'description': '',
            'environment': 'unknown',
            'tags': [],
            'location': '',
            'password': '',
            'totp_secret': '',
            'totp_prompt': ''
        }

        # 读取 config 文件，查找该 Host 前的注释
        if not os.path.exists(self.config_path):
            return metadata

        with open(self.config_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # 查找 Host 行
        host_line_index = -1
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('Host ') and not stripped.startswith('Host *'):
                import re
                match = re.match(r'Host\s+(.+)', stripped)
                if match and match.group(1).strip() == alias:
                    host_line_index = i
                    break

        if host_line_index == -1:
            return metadata

        # 向前查找注释
        comment_lines = []
        i = host_line_index - 1
        while i >= 0:
            line = lines[i]
            stripped = line.strip()
            if stripped.startswith('#') or not stripped:
                comment_lines.insert(0, line)
                i -= 1
            else:
                break

        # 解析注释
        for line in comment_lines:
            line = line.strip()
            if not line.startswith('#'):
                continue

            # 移除开头的 #
            line = line[1:].strip()

            # 跳过分隔线
            if line.startswith('=====') or line == '':
                continue

            # 解析 key: value 格式
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()

                if key == 'description':
                    metadata['description'] = value
                elif key == 'environment':
                    metadata['environment'] = value
                elif key == 'tags':
                    metadata['tags'] = [t.strip() for t in value.split(',') if t.strip()]
                elif key == 'location':
                    metadata['location'] = value
                elif key == 'password':
                    metadata['password'] = value
                elif key == 'totp_secret':
                    metadata['totp_secret'] = value
                elif key == 'totp_prompt':
                    metadata['totp_prompt'] = value

        return metadata

    def get_connection_params(self, alias: str) -> dict:
        """
        获取连接参数（用于创建 SSH 客户端）

        Args:
            alias: 主机别名

        Returns:
            连接参数字典（包括密码）
        """
        config = self.load_ssh_config(alias)
        metadata = self.load_metadata(alias)

        # 提取连接参数
        params = {
            'hostname': config.get('hostname'),
            'user': config.get('user'),
            'port': int(config.get('port', 22)),
            'timeout': 30,  # 默认超时
        }

        # 密钥文件
        identity_files = config.get('identityfile')
        if identity_files:
            # paramiko 返回的是列表
            if isinstance(identity_files, list):
                params['key_file'] = identity_files[0]
            else:
                params['key_file'] = identity_files

        # 密码（从注释元数据中获取）
        if metadata.get('password'):
            params['password'] = metadata['password']

        # TOTP（从注释元数据中获取）
        if metadata.get('totp_secret'):
            params['totp_secret'] = metadata['totp_secret']
        if metadata.get('totp_prompt'):
            params['totp_prompt'] = metadata['totp_prompt']

        # ProxyJump（跳板机）
        proxy_jump = config.get('proxyjump')
        if proxy_jump:
            params['proxy_jump'] = proxy_jump

        proxy_command = config.get('proxycommand')
        if proxy_command:
            params['proxy_command'] = proxy_command

        if proxy_command and not params.get('totp_secret'):
            jump_totp = self._load_proxy_command_totp(proxy_command)
            if jump_totp.get('totp_secret'):
                params['totp_secret'] = jump_totp['totp_secret']
            if jump_totp.get('totp_prompt'):
                params['totp_prompt'] = jump_totp['totp_prompt']

        # ForwardAgent（SSH agent 转发）
        forward_agent = config.get('forwardagent', 'no').lower()
        params['forward_agent'] = forward_agent in ('yes', 'true', '1')

        # 元数据
        params['metadata'] = metadata
        params['alias'] = alias

        return params

    def _load_proxy_command_totp(self, proxy_command: str) -> dict:
        """Load TOTP metadata from a ProxyCommand jump target."""
        result = {'totp_secret': '', 'totp_prompt': ''}

        for jump_host in self._proxy_command_targets(proxy_command):
            jump_alias = self._find_alias_by_hostname(jump_host) or jump_host
            jump_meta = self.load_metadata(jump_alias)
            if jump_meta.get('totp_secret'):
                result['totp_secret'] = jump_meta.get('totp_secret', '')
                result['totp_prompt'] = jump_meta.get('totp_prompt', '')
                return result

        return result

    def _proxy_command_targets(self, proxy_command: str) -> List[str]:
        """Return host aliases used by supported ProxyCommand forms."""
        try:
            tokens = shlex.split(proxy_command)
        except ValueError:
            tokens = proxy_command.split()
        if tokens and tokens[0] == 'exec':
            tokens = tokens[1:]

        if tokens:
            proxy_program = os.path.basename(tokens[0]).lower()
            if proxy_program == 'ssh':
                target = self._target_from_ssh_args(tokens[1:])
                if target:
                    return [self._host_part(target)]
            if proxy_program in {'debug_proxy.cmd', 'debug_proxy.sh', 'debug_proxy_win.py'}:
                return [os.environ.get('SSH_TOTP_JUMP_ALIAS', 'X')]
            if proxy_program in {'sshotp', 'sshotp.cmd', 'ssh_totp.py'} and '--socks' in tokens:
                return [os.environ.get('SSH_TOTP_JUMP_ALIAS', 'X')]
            if len(tokens) > 1 and os.path.basename(tokens[1]).lower() == 'ssh_totp.py' and '--socks' in tokens:
                return [os.environ.get('SSH_TOTP_JUMP_ALIAS', 'X')]

        return [self._host_part(match) for match in re.findall(r'[\w.-]+@([A-Za-z0-9_.-]+)', proxy_command)]

    @staticmethod
    def _target_from_ssh_args(args: List[str]) -> Optional[str]:
        skip_next = False
        options_with_value = {
            '-b', '-c', '-D', '-E', '-e', '-F', '-I', '-i', '-J', '-L',
            '-l', '-m', '-O', '-o', '-p', '-Q', '-R', '-S', '-W', '-w',
        }
        for arg in args:
            if skip_next:
                skip_next = False
                continue
            if arg == '--':
                continue
            if arg in options_with_value:
                skip_next = True
                continue
            if arg.startswith('-'):
                continue
            return arg
        return None

    @staticmethod
    def _host_part(target: str) -> str:
        return target.rsplit('@', 1)[-1]

    def _find_alias_by_hostname(self, hostname: str) -> Optional[str]:
        """Find an explicit Host alias whose HostName equals hostname."""
        aliases = []
        with open(self.config_path, 'r', encoding='utf-8') as handle:
            for raw_line in handle:
                stripped = raw_line.strip()
                lowered = stripped.lower()
                if lowered.startswith('host ') and not lowered.startswith('host *'):
                    aliases.extend(stripped[5:].strip().split())

        for candidate in aliases:
            try:
                config = self.load_ssh_config(candidate)
            except Exception:
                continue
            if config.get('hostname') == hostname or candidate == hostname:
                return candidate

        return None

    def from_alias(self, alias: str):
        """
        通过别名创建 SSH 客户端（智能选择）

        策略：
        - 有密钥文件且无密码 → 使用 NativeSSHClient（原生 SSH）
        - 有密码 → 使用 ParamikoClient（Paramiko）

        Args:
            alias: 主机别名

        Returns:
            NativeSSHClient 或 ParamikoClient 实例
        """
        params = self.get_connection_params(alias)

        has_key = params.get('key_file') is not None
        has_password = params.get('password') is not None
        has_native_ssh_config = (
            params.get('proxy_jump') is not None or
            params.get('proxy_command') is not None or
            params.get('totp_secret') is not None
        )

        # 智能选择客户端类型
        if (has_key or has_native_ssh_config) and not has_password:
            # 原生 SSH 特性 → 使用 OpenSSH
            try:
                from .native_ssh_client import NativeSSHClient
            except ImportError:
                from native_ssh_client import NativeSSHClient

            client = NativeSSHClient(
                host=params['hostname'],
                user=params['user'],
                port=params['port'],
                key_file=params.get('key_file'),
                config_path=self.config_path,
                timeout=params['timeout'],
                proxy_jump=params.get('proxy_jump'),
                forward_agent=params.get('forward_agent', False),
                alias=alias,
                totp_secret=params.get('totp_secret'),
                totp_prompt=params.get('totp_prompt')
            )
        else:
            # 密码认证 → 使用 Paramiko
            try:
                from .paramiko_client import ParamikoClient
            except ImportError:
                from paramiko_client import ParamikoClient

            client = ParamikoClient(
                host=params['hostname'],
                user=params['user'],
                port=params['port'],
                password=params.get('password'),
                key_file=params.get('key_file'),
                timeout=params['timeout']
            )

        # 设置别名（用于守护进程标识）
        client.alias = alias

        return client

    @staticmethod
    def get_default_config_path() -> str:
        """获取默认 SSH config 路径"""
        return os.path.expanduser("~/.ssh/config")

    @staticmethod
    def get_default_metadata_path() -> str:
        """获取默认元数据路径"""
        return os.path.expanduser("~/.ssh/config_metadata.json")


# 向后兼容：提供全局函数接口
def get_config_loader_v3(config_path: Optional[str] = None,
                         metadata_path: Optional[str] = None) -> SSHConfigLoaderV3:
    """
    获取配置加载器实例

    Args:
        config_path: SSH config 文件路径
        metadata_path: 元数据文件路径

    Returns:
        SSHConfigLoaderV3 实例
    """
    return SSHConfigLoaderV3(config_path, metadata_path)
