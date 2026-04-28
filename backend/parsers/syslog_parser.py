#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Syslog格式解析器
支持: secure, auth.log, messages, syslog, cron, mail
格式: MMM DD HH:MM:SS hostname process[pid]: message
"""

import re
from datetime import datetime
from typing import Optional, Dict, Tuple

from .base_parser import BaseParser
from ..core.log_event import LogEvent, EventLevel, EventResult


class SyslogParser(BaseParser):
    """Syslog格式解析器"""
    
    name = "syslog"
    supported_types = ["secure", "auth", "messages", "syslog", "cron", "mail"]
    
    # 主正则
    SYSLOG_PATTERN = re.compile(
        r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+'
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<message>.*)$'
    )
    
    MONTHS = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }
    
    # ==================== SSH事件模式 ====================
    SSH_ACCEPTED_PASSWORD = re.compile(
        r'Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
    )
    SSH_ACCEPTED_PUBLICKEY = re.compile(
        r'Accepted publickey for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+) ssh2: (?P<key_type>\S+) (?P<fingerprint>\S+)'
    )
    SSH_ACCEPTED_KEYBOARD = re.compile(
        r'Accepted keyboard-interactive/pam for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
    )
    SSH_FAILED_PASSWORD = re.compile(
        r'Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
    )
    SSH_INVALID_USER = re.compile(
        r'Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)(?: port (?P<port>\d+))?'
    )
    SSH_SESSION_OPENED = re.compile(
        r'pam_unix\(sshd:session\): session opened for user (?P<user>\S+) by \(uid=(?P<uid>\d+)\)'
    )
    SSH_SESSION_CLOSED = re.compile(
        r'pam_unix\(sshd:session\): session closed for user (?P<user>\S+)'
    )
    SSH_AUTH_FAILURE = re.compile(
        r'pam_unix\(sshd:auth\): authentication failure;.*rhost=(?P<ip>[\d.]+)(?:\s+user=(?P<user>\S+))?'
    )
    SSH_CONNECTION_CLOSED = re.compile(
        r'Connection closed by (?P<ip>[\d.]+)(?: port (?P<port>\d+))?'
    )
    SSH_DISCONNECTED = re.compile(
        r'Disconnected from (?:user (?P<user>\S+) )?(?P<ip>[\d.]+) port (?P<port>\d+)'
    )
    SSH_NO_IDENT = re.compile(
        r'Did not receive identification string from (?P<ip>[\d.]+) port (?P<port>\d+)'
    )
    SSH_BAD_PROTOCOL = re.compile(
        r"Bad protocol version identification '(?P<data>[^']+)' from (?P<ip>[\d.]+)(?: port (?P<port>\d+))?"
    )
    SSH_MAX_AUTH = re.compile(
        r'maximum authentication attempts exceeded for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
    )
    SSH_BREAK_IN = re.compile(
        r'reverse mapping checking getaddrinfo for (?P<hostname>\S+) \[(?P<ip>[\d.]+)\] failed - POSSIBLE BREAK-IN ATTEMPT'
    )
    SSH_KEY_NEGOTIATE = re.compile(
        r'Unable to negotiate with (?P<ip>[\d.]+) port (?P<port>\d+): no matching key exchange method'
    )
    SSH_CONNECTION_RESET = re.compile(
        r'Connection reset by (?P<ip>[\d.]+) port (?P<port>\d+)'
    )
    SSH_RECEIVED_DISCONNECT = re.compile(
        r'Received disconnect from (?P<ip>[\d.]+) port (?P<port>\d+):(?P<code>\d+): (?P<reason>.*)'
    )
    
    # ==================== Sudo事件模式 ====================
    SUDO_COMMAND = re.compile(
        r'(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>[^;]+)\s*;\s*'
        r'USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.+)$'
    )
    SUDO_NOT_IN_SUDOERS = re.compile(
        r'(?P<user>\S+)\s*:\s*user NOT in sudoers'
    )
    SUDO_SESSION_OPENED = re.compile(
        r'pam_unix\(sudo:session\): session opened for user (?P<user>\S+) by (?P<by_user>\S+)\(uid=(?P<uid>\d+)\)'
    )
    SUDO_SESSION_CLOSED = re.compile(
        r'pam_unix\(sudo:session\): session closed for user (?P<user>\S+)'
    )
    
    # ==================== SU事件模式 ====================
    SU_TO_USER = re.compile(
        r'\(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)'
    )
    SU_SESSION_OPENED = re.compile(
        r'pam_unix\(su(?:-l)?:session\): session opened for user (?P<user>\S+) by (?P<by_user>\S+)\(uid=(?P<uid>\d+)\)'
    )
    SU_SESSION_CLOSED = re.compile(
        r'pam_unix\(su(?:-l)?:session\): session closed for user (?P<user>\S+)'
    )
    
    # ==================== CRON事件模式 ====================
    CRON_SESSION_OPENED = re.compile(
        r'pam_unix\(cron:session\): session opened for user (?P<user>\S+) by \(uid=(?P<uid>\d+)\)'
    )
    CRON_SESSION_CLOSED = re.compile(
        r'pam_unix\(cron:session\): session closed for user (?P<user>\S+)'
    )
    CRON_CMD = re.compile(
        r'\((?P<user>\S+)\) CMD \((?P<command>.+)\)'
    )
    
    # ==================== 用户管理事件模式 ====================
    USER_ADD = re.compile(
        r'new user: name=(?P<user>\S+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), home=(?P<home>[^,]+), shell=(?P<shell>\S+)'
    )
    USER_DEL = re.compile(
        r"delete user '(?P<user>\S+)'"
    )
    USER_MOD = re.compile(
        r"add '(?P<user>\S+)' to group '(?P<group>\S+)'"
    )
    GROUP_ADD = re.compile(
        r'group added to /etc/group: name=(?P<group>\S+), GID=(?P<gid>\d+)'
    )
    PASSWD_CHANGED = re.compile(
        r'pam_unix\(passwd:chauthtok\): password changed for (?P<user>\S+)'
    )
    
    # ==================== 本地登录事件模式 ====================
    ROOT_LOGIN = re.compile(
        r"ROOT LOGIN on '(?P<tty>[^']+)'"
    )
    LOGIN_SESSION_OPENED = re.compile(
        r'pam_unix\(login:session\): session opened for user (?P<user>\S+) by (?:LOGIN\(uid=(?P<uid>\d+)\)|(?P<by_user>\S+))'
    )
    LOGIN_SESSION_CLOSED = re.compile(
        r'pam_unix\(login:session\): session closed for user (?P<user>\S+)'
    )
    
    # ==================== systemd-logind事件模式 ====================
    SYSTEMD_NEW_SESSION = re.compile(
        r'New session (?P<session>\S+) of user (?P<user>\S+)'
    )
    SYSTEMD_REMOVED_SESSION = re.compile(
        r'Removed session (?P<session>\S+)'
    )
    
    # ==================== SSH服务器事件模式 ====================
    SSH_SERVER_LISTENING = re.compile(
        r'Server listening on (?P<addr>\S+) port (?P<port>\d+)'
    )
    SSH_TOO_MANY_AUTH = re.compile(
        r'Disconnecting.*Too many authentication failures'
    )
    SSH_PAM_CHECK_PASS = re.compile(
        r'pam_unix\(sshd:auth\): check pass; user unknown'
    )
    SSH_NO_MORE_SESSIONS = re.compile(
        r'sshd.*: no more sessions'
    )
    SSH_UID_REQUIREMENT = re.compile(
        r'requirement "?uid >= \d+"? not met by user "?(?P<user>[^"]+)"?'
    )
    SSH_REFUSED_CONNECT = re.compile(
        r'refused connect from (?P<hostname>\S+) \((?P<ip>[\d.]+)\)'
    )
    SSH_PAM_IGNORING_RETRIES = re.compile(
        r'PAM service\(sshd\) ignoring max retries; (?P<attempts>\d+) > (?P<max>\d+)'
    )
    SSH_PAM_MORE_FAILURES = re.compile(
        r'PAM (?P<count>\d+) more authentication failures;.*rhost=(?P<ip>[\d.]+)'
    )
    SSH_PREAUTH_INVALID_USER = re.compile(
        r'input_userauth_request: invalid user (?P<user>\S*) \[preauth\]'
    )
    SSH_SFTP_SUBSYSTEM = re.compile(
        r'subsystem request for sftp'
    )
    SSH_DISCONNECTED_BY_USER = re.compile(
        r'disconnected by user'
    )
    SSH_INCOMPLETE_MESSAGE = re.compile(
        r'incomplete message \[preauth\]'
    )
    SSH_DH_GEX_OUT_OF_RANGE = re.compile(
        r'DH GEX group out of range \[preauth\]'
    )
    SSH_NO_MORE_SESSIONS = re.compile(
        r'no more sessions'
    )
    SSH_CONNECTION_RESET_PEER = re.compile(
        r'Connection reset by peer'
    )
    
    # 新增SSH事件模式
    SSH_PAM_AUTH_FAILURE = re.compile(
        r'error: PAM: Authentication failure for (?P<user>\S+) from (?P<ip>[\d.]+)'
    )
    SSH_ACCOUNT_LOCKED = re.compile(
        r'error: PAM: User account (?:locked|has expired) for (?P<user>\S+) from (?P<ip>[\d.]+)'
    )
    SSH_FAILED_LOCKED_USER = re.compile(
        r'Failed password for locked user (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
    )
    SSH_INVALID_USER_EMPTY = re.compile(
        r'Invalid user\s+from (?P<ip>[\d.]+)(?: port (?P<port>\d+))?'
    )
    
    # 通用会话事件模式
    GENERIC_SESSION_OPENED = re.compile(
        r'session opened for user (?P<user>\S+) by \(uid=(?P<uid>\d+)\)'
    )
    GENERIC_SESSION_CLOSED = re.compile(
        r'session closed for user (?P<user>\S+)'
    )
    
    # ==================== 防火墙事件模式 ====================
    UFW_BLOCK = re.compile(
        r'\[UFW BLOCK\].*SRC=(?P<src_ip>[\d.]+).*DST=(?P<dst_ip>[\d.]+).*PROTO=(?P<proto>\S+)'
    )
    UFW_ALLOW = re.compile(
        r'\[UFW ALLOW\].*SRC=(?P<src_ip>[\d.]+).*DST=(?P<dst_ip>[\d.]+).*PROTO=(?P<proto>\S+)'
    )
    IPTABLES_BLOCK = re.compile(
        r'(?:iptables|kernel).*(?:BLOCK|DROP|REJECT).*SRC=(?P<src_ip>[\d.]+).*DST=(?P<dst_ip>[\d.]+)'
    )
    
    # ==================== PAM认证失败计数 ====================
    PAM_TALLY = re.compile(
        r'(?:(?P<user>\S+):\s*)?auth failure tally (?P<tally>\d+), deny (?P<deny>\d+)'
    )
    PAM_FAILLOCK = re.compile(
        r'pam_faillock.*user (?P<user>\S+).*(?:locked|unlocked)'
    )
    
    # ==================== Sudo事件扩展模式 ====================
    SUDO_AUTH_FAILURE = re.compile(
        r'pam_unix\(sudo:auth\): authentication failure;.*user=(?P<user>\S+)'
    )
    SUDO_INCORRECT_PASSWORD = re.compile(
        r'(?P<user>\S+)\s*:\s*(?P<attempts>\d+) incorrect password attempts?'
    )
    SUDO_3_INCORRECT = re.compile(
        r'(?P<user>\S+)\s*:\s*3 incorrect password attempts'
    )
    
    # ==================== 本地登录事件模式 ====================
    ROOT_LOGIN_ON = re.compile(
        r'ROOT LOGIN ON (?P<tty>\S+)'
    )
    FAILED_LOGIN = re.compile(
        r'FAILED LOGIN (?P<attempts>\d+) FROM (?P<source>\S+) FOR (?P<user>\S+)'
    )
    LOGIN_AUTH_FAILURE = re.compile(
        r'pam_unix\(login:auth\): authentication failure;.*user=(?P<user>\S+)'
    )
    
    # ==================== 密码检查事件 ====================
    PASSWORD_CHECK_FAILED = re.compile(
        r'password check failed for user \((?P<user>\S+)\)'
    )
    
    # ==================== GNOME Keyring事件 ====================
    GKR_PAM = re.compile(
        r"gkr-pam: couldn't update the '(?P<keyring>\S+)' keyring password"
    )
    
    # ==================== 组管理事件 ====================
    NEW_GROUP = re.compile(
        r'new group: name=(?P<group>\S+), GID=(?P<gid>\d+)'
    )
    
    # ==================== 事件类型映射 ====================
    # 从独立的事件映射文件导入
    from ..core.event_mappings import ALL_EVENT_TYPES, get_event_tuple, EventLevel as EL
    
    # 兼容旧格式的EVENT_TYPES
    EVENT_TYPES = {
        event_type: (info.name, info.category, info.level, info.result)
        for event_type, info in ALL_EVENT_TYPES.items()
    }
    
    def __init__(self, log_type: str = "", source_file: str = ""):
        super().__init__(log_type)
        self.current_year = datetime.now().year
        self.source_file = source_file
        self._year_info = None
    
    def set_year(self, year: int):
        """手动设置年份"""
        self.current_year = year
    
    def set_source_file(self, file_path: str):
        """设置源文件路径，用于智能年份检测"""
        self.source_file = file_path
        # 使用年份解析器
        from ..core.year_resolver import year_resolver
        self._year_info = year_resolver.resolve_year(file_path)
        self.current_year = self._year_info.get("year", datetime.now().year)
    
    def get_year_info(self) -> dict:
        """获取年份信息"""
        return self._year_info or {"year": self.current_year, "source": "default"}
    
    def parse_line(self, line: str, record_id: int = 0) -> Optional[LogEvent]:
        """解析单行syslog日志"""
        if not line.strip():
            return None
        
        match = self.SYSLOG_PATTERN.match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        
        # Parse time戳
        timestamp = self._parse_timestamp(
            groups['month'], groups['day'], groups['time']
        )
        
        # Create event
        event = LogEvent(
            record_id=record_id,
            log_type=self.log_type,
            hostname=groups['hostname'],
            process=groups['process'].strip(),
            pid=int(groups['pid']) if groups['pid'] else None,
            message=groups['message'],
        )
        
        if timestamp:
            event.set_timestamp(ts=timestamp)
        
        # 解析消息内容
        self._parse_message(event, groups['message'], groups['process'].strip().lower())
        
        return event
    
    def _parse_timestamp(self, month: str, day: str, time_str: str) -> Optional[datetime]:
        """解析时间戳"""
        try:
            month_num = self.MONTHS.get(month, 1)
            day_num = int(day)
            hour, minute, second = map(int, time_str.split(':'))
            
            year = self.current_year
            current_month = datetime.now().month
            if month_num > current_month + 1:
                year -= 1
            
            return datetime(year, month_num, day_num, hour, minute, second)
        except:
            return None
    
    def _parse_message(self, event: LogEvent, message: str, process: str):
        """解析消息内容"""
        # 先检查消息内容中的特殊模式
        if 'gkr-pam' in message:
            self._parse_gkr_pam(event, message)
            return
        
        # 防火墙事件 (UFW, iptables)
        if '[UFW' in message or 'iptables' in message.lower():
            self._parse_firewall(event, message)
            return
        
        # PAM认证失败计数
        if 'auth failure tally' in message:
            self._parse_pam_tally(event, message)
            return
        
        # SSH相关
        if 'sshd' in process:
            self._parse_ssh(event, message)
        # Sudo相关
        elif 'sudo' in process:
            self._parse_sudo(event, message)
        # SU相关
        elif process == 'su':
            self._parse_su(event, message)
        # CRON相关
        elif 'cron' in process:
            self._parse_cron(event, message)
        # 用户管理
        elif process in ['useradd', 'userdel', 'usermod', 'groupadd', 'passwd']:
            self._parse_user_mgmt(event, message, process)
        # systemd-logind (必须在login之前检查)
        elif 'systemd' in process.lower():
            self._parse_systemd_logind(event, message)
        # 本地登录
        elif 'login' in process:
            self._parse_login(event, message)
        # polkitd
        elif 'polkitd' in process:
            self._set_event_type(event, 'POLKIT')
        # unix_chkpwd
        elif 'unix_chkpwd' in process:
            self._parse_unix_chkpwd(event, message)
        # groupadd
        elif 'groupadd' in process:
            self._parse_groupadd(event, message)
        # firewall进程
        elif 'firewall' in process.lower() or 'ufw' in process.lower():
            self._parse_firewall(event, message)
        # 通用消息处理
        else:
            self._parse_generic(event, message, process)
    
    def _set_event_type(self, event: LogEvent, event_type: str):
        """设置事件类型（从映射表获取信息）"""
        info = self.EVENT_TYPES.get(event_type)
        if info:
            event.event_type = event_type
            event.event_name = info[0]
            event.event_category = info[1]
            event.level = info[2]
            event.result = info[3]
        else:
            # 如果映射表中没有，使用默认值
            event.event_type = event_type
            event.event_name = event_type
            event.event_category = '其他'
    
    def _set_event_info(self, event: LogEvent, event_type: str, groups: Dict):
        """设置事件信息"""
        self._set_event_type(event, event_type)
        
        # 提取通用字段
        if 'user' in groups and groups['user']:
            event.user = groups['user']
        if 'ip' in groups and groups['ip']:
            event.source_ip = groups['ip']
        if 'port' in groups and groups['port']:
            event.source_port = int(groups['port'])
        if 'uid' in groups and groups['uid']:
            event.uid = int(groups['uid'])
        if 'target' in groups and groups['target']:
            event.target_user = groups['target']
    
    def _parse_ssh(self, event: LogEvent, message: str):
        """解析SSH消息"""
        patterns = [
            ('SSH_ACCEPTED_PASSWORD', self.SSH_ACCEPTED_PASSWORD),
            ('SSH_ACCEPTED_PUBLICKEY', self.SSH_ACCEPTED_PUBLICKEY),
            ('SSH_ACCEPTED_KEYBOARD', self.SSH_ACCEPTED_KEYBOARD),
            ('SSH_FAILED_PASSWORD', self.SSH_FAILED_PASSWORD),
            ('SSH_FAILED_LOCKED_USER', self.SSH_FAILED_LOCKED_USER),
            ('SSH_INVALID_USER', self.SSH_INVALID_USER),
            ('SSH_INVALID_USER_EMPTY', self.SSH_INVALID_USER_EMPTY),
            ('SSH_SESSION_OPENED', self.SSH_SESSION_OPENED),
            ('SSH_SESSION_CLOSED', self.SSH_SESSION_CLOSED),
            ('SSH_AUTH_FAILURE', self.SSH_AUTH_FAILURE),
            ('SSH_PAM_AUTH_FAILURE', self.SSH_PAM_AUTH_FAILURE),
            ('SSH_ACCOUNT_LOCKED', self.SSH_ACCOUNT_LOCKED),
            ('SSH_CONNECTION_CLOSED', self.SSH_CONNECTION_CLOSED),
            ('SSH_DISCONNECTED', self.SSH_DISCONNECTED),
            ('SSH_NO_IDENT', self.SSH_NO_IDENT),
            ('SSH_BAD_PROTOCOL', self.SSH_BAD_PROTOCOL),
            ('SSH_MAX_AUTH', self.SSH_MAX_AUTH),
            ('SSH_BREAK_IN', self.SSH_BREAK_IN),
            ('SSH_KEY_NEGOTIATE', self.SSH_KEY_NEGOTIATE),
            ('SSH_CONNECTION_RESET', self.SSH_CONNECTION_RESET),
            ('SSH_RECEIVED_DISCONNECT', self.SSH_RECEIVED_DISCONNECT),
            ('SSH_SERVER_LISTENING', self.SSH_SERVER_LISTENING),
            ('SSH_TOO_MANY_AUTH', self.SSH_TOO_MANY_AUTH),
            ('SSH_PAM_CHECK_PASS', self.SSH_PAM_CHECK_PASS),
            ('SSH_NO_MORE_SESSIONS', self.SSH_NO_MORE_SESSIONS),
            ('SSH_UID_REQUIREMENT', self.SSH_UID_REQUIREMENT),
            ('SSH_REFUSED_CONNECT', self.SSH_REFUSED_CONNECT),
            ('SSH_PAM_IGNORING_RETRIES', self.SSH_PAM_IGNORING_RETRIES),
            ('SSH_PAM_MORE_FAILURES', self.SSH_PAM_MORE_FAILURES),
            ('SSH_PREAUTH_INVALID_USER', self.SSH_PREAUTH_INVALID_USER),
            ('SSH_SFTP_SUBSYSTEM', self.SSH_SFTP_SUBSYSTEM),
            ('SSH_DISCONNECTED_BY_USER', self.SSH_DISCONNECTED_BY_USER),
            ('SSH_INCOMPLETE_MESSAGE', self.SSH_INCOMPLETE_MESSAGE),
            ('SSH_DH_GEX_OUT_OF_RANGE', self.SSH_DH_GEX_OUT_OF_RANGE),
            ('SSH_NO_MORE_SESSIONS', self.SSH_NO_MORE_SESSIONS),
            ('SSH_CONNECTION_RESET_PEER', self.SSH_CONNECTION_RESET_PEER),
        ]
        
        for event_type, pattern in patterns:
            match = pattern.search(message)
            if match:
                self._set_event_info(event, event_type, match.groupdict())
                
                # 特殊处理
                if event_type == 'SSH_FAILED_PASSWORD' and match.group('invalid'):
                    event.extra['invalid_user'] = True
                if event_type == 'SSH_ACCEPTED_PUBLICKEY':
                    event.extra['key_type'] = match.group('key_type')
                    event.extra['fingerprint'] = match.group('fingerprint')
                if event_type == 'SSH_BAD_PROTOCOL':
                    event.extra['bad_data'] = match.group('data')
                if event_type == 'SSH_BREAK_IN':
                    event.extra['reverse_hostname'] = match.group('hostname')
                
                return
        
        # 未匹配的SSH消息，提取IP
        ip_match = re.search(r'from (?P<ip>[\d.]+)(?: port (?P<port>\d+))?', message)
        if ip_match:
            event.source_ip = ip_match.group('ip')
            if ip_match.group('port'):
                event.source_port = int(ip_match.group('port'))
        
        # 设置为通用SSH事件
        self._set_event_type(event, 'SSH_OTHER')
    

    
    def _parse_sudo(self, event: LogEvent, message: str):
        """解析Sudo消息"""
        patterns = [
            ('SUDO_COMMAND', self.SUDO_COMMAND),
            ('SUDO_NOT_IN_SUDOERS', self.SUDO_NOT_IN_SUDOERS),
            ('SUDO_SESSION_OPENED', self.SUDO_SESSION_OPENED),
            ('SUDO_SESSION_CLOSED', self.SUDO_SESSION_CLOSED),
            ('SUDO_AUTH_FAILURE', self.SUDO_AUTH_FAILURE),
            ('SUDO_INCORRECT_PASSWORD', self.SUDO_INCORRECT_PASSWORD),
            ('SUDO_3_INCORRECT_ATTEMPTS', self.SUDO_3_INCORRECT),
        ]
        
        for event_type, pattern in patterns:
            match = pattern.search(message)
            if match:
                self._set_event_info(event, event_type, match.groupdict())
                
                if event_type == 'SUDO_COMMAND':
                    event.extra['tty'] = match.group('tty')
                    event.extra['pwd'] = match.group('pwd')
                    event.extra['command'] = match.group('command')
                if event_type == 'SUDO_SESSION_OPENED':
                    event.extra['by_user'] = match.group('by_user')
                if event_type == 'SUDO_INCORRECT_PASSWORD':
                    event.extra['attempts'] = match.group('attempts')
                
                return
        
        # 如果没有匹配到任何模式，设置为通用消息
        self._set_event_type(event, 'GENERIC')
    
    def _parse_su(self, event: LogEvent, message: str):
        """解析SU消息"""
        patterns = [
            ('SU_TO_USER', self.SU_TO_USER),
            ('SU_SESSION_OPENED', self.SU_SESSION_OPENED),
            ('SU_SESSION_CLOSED', self.SU_SESSION_CLOSED),
        ]
        
        for event_type, pattern in patterns:
            match = pattern.search(message)
            if match:
                self._set_event_info(event, event_type, match.groupdict())
                
                if event_type == 'SU_TO_USER':
                    event.extra['tty'] = match.group('tty')
                if event_type == 'SU_SESSION_OPENED':
                    event.extra['by_user'] = match.group('by_user')
                
                return
    
    def _parse_cron(self, event: LogEvent, message: str):
        """解析CRON消息"""
        patterns = [
            ('CRON_SESSION_OPENED', self.CRON_SESSION_OPENED),
            ('CRON_SESSION_CLOSED', self.CRON_SESSION_CLOSED),
            ('CRON_CMD', self.CRON_CMD),
        ]
        
        for event_type, pattern in patterns:
            match = pattern.search(message)
            if match:
                self._set_event_info(event, event_type, match.groupdict())
                
                if event_type == 'CRON_CMD':
                    event.extra['command'] = match.group('command')
                
                return
    
    def _parse_user_mgmt(self, event: LogEvent, message: str, process: str):
        """解析用户管理消息"""
        patterns = [
            ('USER_ADD', self.USER_ADD),
            ('USER_DEL', self.USER_DEL),
            ('USER_MOD', self.USER_MOD),
            ('GROUP_ADD', self.GROUP_ADD),
            ('PASSWD_CHANGED', self.PASSWD_CHANGED),
        ]
        
        for event_type, pattern in patterns:
            match = pattern.search(message)
            if match:
                self._set_event_info(event, event_type, match.groupdict())
                
                groups = match.groupdict()
                if 'gid' in groups:
                    event.extra['gid'] = int(groups['gid'])
                if 'home' in groups:
                    event.extra['home'] = groups['home']
                if 'shell' in groups:
                    event.extra['shell'] = groups['shell']
                if 'group' in groups:
                    event.extra['group'] = groups['group']
                
                return
    
    def _parse_login(self, event: LogEvent, message: str):
        """解析本地登录消息"""
        patterns = [
            ('ROOT_LOGIN', self.ROOT_LOGIN),
            ('ROOT_LOGIN_ON', self.ROOT_LOGIN_ON),
            ('LOGIN_SESSION_OPENED', self.LOGIN_SESSION_OPENED),
            ('LOGIN_SESSION_CLOSED', self.LOGIN_SESSION_CLOSED),
            ('FAILED_LOGIN', self.FAILED_LOGIN),
            ('LOGIN_AUTH_FAILURE', self.LOGIN_AUTH_FAILURE),
        ]
        
        for event_type, pattern in patterns:
            match = pattern.search(message)
            if match:
                self._set_event_info(event, event_type, match.groupdict())
                
                if event_type in ['ROOT_LOGIN', 'ROOT_LOGIN_ON']:
                    event.user = 'root'
                    if 'tty' in match.groupdict():
                        event.extra['tty'] = match.group('tty')
                if event_type == 'FAILED_LOGIN':
                    event.extra['attempts'] = match.group('attempts')
                    event.extra['source'] = match.group('source')
                
                return
    
    def _parse_systemd_logind(self, event: LogEvent, message: str):
        """解析systemd-logind消息"""
        # 处理 "New session X of user Y" 格式
        new_match = re.search(r'New session (\S+) of user (\S+?)\.?$', message)
        if new_match:
            self._set_event_type(event, 'SYSTEMD_NEW_SESSION')
            event.extra['session_id'] = new_match.group(1)
            event.user = new_match.group(2)
            return
        
        # 处理 "Removed session X" 格式
        removed_match = re.search(r'Removed session (\S+?)\.?$', message)
        if removed_match:
            self._set_event_type(event, 'SYSTEMD_REMOVED_SESSION')
            event.extra['session_id'] = removed_match.group(1)
            return
        
        # 处理 "Started Session X of user Y" 格式
        started_match = re.search(r'Started Session (\S+) of user (\S+?)\.?$', message)
        if started_match:
            self._set_event_type(event, 'SYSTEMD_NEW_SESSION')
            event.extra['session_id'] = started_match.group(1)
            event.user = started_match.group(2)
            return
        
        # 处理 "Starting Session X of user Y" 格式
        starting_match = re.search(r'Starting Session (\S+) of user (\S+?)\.?$', message)
        if starting_match:
            self._set_event_type(event, 'SYSTEMD_STARTING_SESSION')
            event.extra['session_id'] = starting_match.group(1)
            event.user = starting_match.group(2)
            return
        
        # 处理 slice 相关消息
        if 'slice' in message.lower():
            if 'Created slice' in message or 'Started slice' in message:
                self._set_event_type(event, 'SYSTEMD_SLICE_CREATED')
            elif 'Removed slice' in message:
                self._set_event_type(event, 'SYSTEMD_SLICE_REMOVED')
            elif 'Stopping' in message:
                self._set_event_type(event, 'SYSTEMD_SLICE_STOPPING')
            else:
                self._set_event_type(event, 'SYSTEMD_SLICE')
            # 提取用户
            user_match = re.search(r'user-(\d+)\.slice', message)
            if user_match:
                event.extra['uid'] = user_match.group(1)
            return
        
        # 其他systemd消息
        self._set_event_type(event, 'SYSTEMD_OTHER')
    
    def _parse_gkr_pam(self, event: LogEvent, message: str):
        """解析GNOME Keyring消息"""
        match = self.GKR_PAM.search(message)
        if match:
            self._set_event_info(event, 'GKR_PAM', match.groupdict())
            event.extra['keyring'] = match.group('keyring')
    
    def _parse_unix_chkpwd(self, event: LogEvent, message: str):
        """解析unix_chkpwd消息"""
        match = self.PASSWORD_CHECK_FAILED.search(message)
        if match:
            self._set_event_info(event, 'PASSWORD_CHECK_FAILED', match.groupdict())
    
    def _parse_groupadd(self, event: LogEvent, message: str):
        """解析groupadd消息"""
        match = self.NEW_GROUP.search(message)
        if match:
            self._set_event_info(event, 'NEW_GROUP', match.groupdict())
            event.extra['group'] = match.group('group')
            event.extra['gid'] = match.group('gid')
    
    def _parse_generic(self, event: LogEvent, message: str, process: str):
        """解析通用消息"""
        # rsyslogd消息
        if 'rsyslogd' in process or 'rsyslog' in message:
            self._set_event_type(event, 'RSYSLOG')
            return
        
        # auditd消息
        if 'auditd' in process or 'Audit daemon' in message:
            self._set_event_type(event, 'AUDITD')
            return
        
        # kernel消息
        if 'kernel' in process:
            self._set_event_type(event, 'KERNEL')
            return
        
        # chronyd/ntpd时间同步
        if 'chronyd' in process or 'ntpd' in process or 'Selected source' in message:
            self._set_event_type(event, 'TIME_SYNC')
            return
        
        # systemd-tmpfiles
        if 'systemd-tmpfiles' in process or 'Cleanup of Temporary' in message:
            self._set_event_type(event, 'SYSTEMD_TMPFILES')
            return
        
        # aide/rkhunter等安全检查
        if 'SelfCheck' in message or 'Database status' in message:
            self._set_event_type(event, 'SECURITY_CHECK')
            return
        
        # imjournal
        if 'imjournal' in message:
            self._set_event_type(event, 'IMJOURNAL')
            return
        
        # 通用会话事件
        session_opened_match = self.GENERIC_SESSION_OPENED.search(message)
        if session_opened_match:
            self._set_event_info(event, 'GENERIC_SESSION_OPENED', session_opened_match.groupdict())
            return
        
        session_closed_match = self.GENERIC_SESSION_CLOSED.search(message)
        if session_closed_match:
            self._set_event_info(event, 'GENERIC_SESSION_CLOSED', session_closed_match.groupdict())
            return
        
        # 默认设置为通用消息
        self._set_event_type(event, 'GENERIC')
    
    def _parse_firewall(self, event: LogEvent, message: str):
        """解析防火墙消息"""
        # UFW BLOCK
        ufw_block_match = self.UFW_BLOCK.search(message)
        if ufw_block_match:
            self._set_event_type(event, 'UFW_BLOCK')
            event.source_ip = ufw_block_match.group('src_ip')
            event.extra['dst_ip'] = ufw_block_match.group('dst_ip')
            event.extra['proto'] = ufw_block_match.group('proto')
            # 提取端口
            dpt_match = re.search(r'DPT=(\d+)', message)
            if dpt_match:
                event.extra['dst_port'] = dpt_match.group(1)
            spt_match = re.search(r'SPT=(\d+)', message)
            if spt_match:
                event.source_port = int(spt_match.group(1))
            return
        
        # UFW ALLOW
        ufw_allow_match = self.UFW_ALLOW.search(message)
        if ufw_allow_match:
            self._set_event_type(event, 'UFW_ALLOW')
            event.source_ip = ufw_allow_match.group('src_ip')
            event.extra['dst_ip'] = ufw_allow_match.group('dst_ip')
            event.extra['proto'] = ufw_allow_match.group('proto')
            return
        
        # iptables BLOCK
        iptables_match = self.IPTABLES_BLOCK.search(message)
        if iptables_match:
            self._set_event_type(event, 'IPTABLES_BLOCK')
            event.source_ip = iptables_match.group('src_ip')
            event.extra['dst_ip'] = iptables_match.group('dst_ip')
            return
        
        # 通用防火墙阻止
        if 'BLOCK' in message or 'DROP' in message or 'REJECT' in message:
            self._set_event_type(event, 'FIREWALL_BLOCK')
            # 尝试提取IP
            src_match = re.search(r'SRC=([\d.]+)', message)
            if src_match:
                event.source_ip = src_match.group(1)
            return
        
        # 默认
        self._set_event_type(event, 'GENERIC')
    
    def _parse_pam_tally(self, event: LogEvent, message: str):
        """解析PAM认证失败计数"""
        match = self.PAM_TALLY.search(message)
        if match:
            self._set_event_type(event, 'PAM_TALLY')
            user = match.group('user')
            if user:
                event.user = user
            # 如果没有从消息中提取到用户名，使用进程名（如果是用户名格式）
            elif event.process and not event.process.startswith('['):
                event.user = event.process
            event.extra['tally'] = match.group('tally')
            event.extra['deny'] = match.group('deny')
            return
        
        # faillock
        faillock_match = self.PAM_FAILLOCK.search(message)
        if faillock_match:
            self._set_event_type(event, 'PAM_FAILLOCK')
            event.user = faillock_match.group('user')
            return
        
        self._set_event_type(event, 'GENERIC')
