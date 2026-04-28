#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
统一日志事件数据结构
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List


@dataclass
class LogEvent:
    """
    统一日志事件结构
    所有解析器输出统一格式
    """
    # ========== 基础字段 ==========
    record_id: int = 0                      # 记录ID
    log_type: str = ""                      # 日志类型: audit, secure, btmp...
    
    # ========== 时间字段(统一格式) ==========
    timestamp: Optional[datetime] = None    # datetime对象
    timestamp_str: str = ""                 # 显示格式: 2024-11-01 03:23:39
    timestamp_unix: int = 0                 # Unix时间戳(秒)
    timestamp_usec: int = 0                 # 微秒部分
    
    # ========== 来源字段 ==========
    hostname: str = ""                      # 主机名
    source_file: str = ""                   # 来源文件
    
    # ========== 进程字段 ==========
    process: str = ""                       # 进程名
    pid: Optional[int] = None               # 进程ID
    
    # ========== 用户字段 ==========
    user: str = ""                          # 用户名
    uid: Optional[int] = None               # 用户ID
    target_user: str = ""                   # 目标用户(sudo/su)
    
    # ========== 网络字段 ==========
    source_ip: str = ""                     # 来源IP
    source_port: Optional[int] = None       # 来源端口
    dest_ip: str = ""                       # 目标IP
    dest_port: Optional[int] = None         # 目标端口
    
    # ========== 事件字段 ==========
    event_type: str = ""                    # 事件类型代码
    event_name: str = ""                    # 事件名称(中文)
    event_category: str = ""                # 事件分类
    level: str = "INFO"                     # 级别: INFO, WARNING, ERROR, CRITICAL
    result: str = ""                        # 结果: success, failed, denied
    
    # ========== 消息字段 ==========
    message: str = ""                       # 原始消息/描述
    raw_line: str = ""                      # 原始日志行
    
    # ========== 扩展字段 ==========
    extra: Dict[str, Any] = field(default_factory=dict)
    
    # ========== Audit专用字段 ==========
    audit_type: str = ""                    # 审计类型
    audit_serial: int = 0                   # 审计序列号
    auid: Optional[int] = None              # 审计用户ID
    session_id: Optional[int] = None        # 会话ID
    exe: str = ""                           # 执行程序路径
    terminal: str = ""                      # 终端
    operation: str = ""                     # 操作类型
    subj: str = ""                          # SELinux主体上下文
    grantors: str = ""                      # PAM授权模块
    
    # ========== Audit msg内部字段 ==========
    audit_op: str = ""                      # 操作类型 (PAM:authentication, login等)
    audit_acct: str = ""                    # 账户名
    audit_id: Optional[int] = None          # 用户ID (LOGIN类型)
    
    # ========== CRYPTO_KEY_USER专用字段 ==========
    crypto_fp: str = ""                     # 密钥指纹
    crypto_kind: str = ""                   # 密钥类型 (server/client/session)
    crypto_direction: str = ""              # 方向
    crypto_spid: Optional[int] = None       # 子进程ID
    crypto_suid: Optional[int] = None       # 子进程UID
    crypto_laddr: str = ""                  # 本地地址
    crypto_lport: Optional[int] = None      # 本地端口
    crypto_rport: Optional[int] = None      # 远程端口
    crypto_cipher: str = ""                 # 加密算法
    crypto_ksize: Optional[int] = None      # 密钥大小
    
    # ========== SERVICE_*专用字段 ==========
    service_unit: str = ""                  # systemd单元名
    service_comm: str = ""                  # 命令名
    
    # ========== 计算字段 ==========
    user_display: str = ""                  # 用户显示名
    exe_short: str = ""                     # 程序短名
    is_success: bool = False                # 是否成功
    is_remote: bool = False                 # 是否远程
    
    # ========== 二进制日志专用字段 ==========
    line: str = ""                          # 终端行(tty)
    ut_type: int = 0                        # utmp记录类型
    ut_type_name: str = ""                  # utmp类型名称
    
    def set_timestamp(self, ts: datetime = None, unix_ts: int = 0, usec: int = 0):
        """
        设置时间戳(统一入口)
        
        Args:
            ts: datetime对象
            unix_ts: Unix时间戳(秒)
            usec: 微秒
        """
        if ts:
            self.timestamp = ts
            self.timestamp_unix = int(ts.timestamp())
            self.timestamp_usec = usec or ts.microsecond
        elif unix_ts > 0:
            try:
                self.timestamp = datetime.fromtimestamp(unix_ts)
                self.timestamp_unix = unix_ts
                self.timestamp_usec = usec
            except:
                pass
        
        if self.timestamp:
            if self.timestamp_usec:
                self.timestamp_str = self.timestamp.strftime('%Y-%m-%d %H:%M:%S') + f'.{self.timestamp_usec:06d}'
            else:
                self.timestamp_str = self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'record_id': self.record_id,
            'log_type': self.log_type,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'timestamp_str': self.timestamp_str,
            'timestamp_unix': self.timestamp_unix,
            'hostname': self.hostname,
            'source_file': self.source_file,
            'process': self.process,
            'pid': self.pid,
            'user': self.user,
            'uid': self.uid,
            'target_user': self.target_user,
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'event_type': self.event_type,
            'event_name': self.event_name,
            'event_category': self.event_category,
            'level': self.level,
            'result': self.result,
            'message': self.message,
            'raw_line': self.raw_line,
            'extra': self.extra,
            # Audit字段
            'audit_type': self.audit_type,
            'audit_serial': self.audit_serial,
            'auid': self.auid,
            'session_id': self.session_id,
            'exe': self.exe,
            'terminal': self.terminal,
            'operation': self.operation,
            'subj': self.subj,
            'grantors': self.grantors,
            # Audit msg内部字段
            'audit_op': self.audit_op,
            'audit_acct': self.audit_acct,
            'audit_id': self.audit_id,
            # CRYPTO字段
            'crypto_fp': self.crypto_fp,
            'crypto_kind': self.crypto_kind,
            'crypto_direction': self.crypto_direction,
            'crypto_spid': self.crypto_spid,
            'crypto_suid': self.crypto_suid,
            'crypto_laddr': self.crypto_laddr,
            'crypto_lport': self.crypto_lport,
            'crypto_rport': self.crypto_rport,
            'crypto_cipher': self.crypto_cipher,
            'crypto_ksize': self.crypto_ksize,
            # SERVICE字段
            'service_unit': self.service_unit,
            'service_comm': self.service_comm,
            # 计算字段
            'user_display': self.user_display,
            'exe_short': self.exe_short,
            'is_success': self.is_success,
            'is_remote': self.is_remote,
            # 二进制日志字段
            'line': self.line,
            'ut_type': self.ut_type,
            'ut_type_name': self.ut_type_name,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogEvent':
        """从字典创建"""
        event = cls()
        for key, value in data.items():
            if hasattr(event, key):
                if key == 'timestamp' and value:
                    try:
                        event.timestamp = datetime.fromisoformat(value)
                    except:
                        pass
                elif key == 'extra' and isinstance(value, dict):
                    event.extra = value
                else:
                    setattr(event, key, value)
        return event


# 事件级别定义
class EventLevel:
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


# 事件结果定义
class EventResult:
    SUCCESS = "success"
    FAILED = "failed"
    DENIED = "denied"
    UNKNOWN = ""
