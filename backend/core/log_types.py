#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
日志类型定义
"""

import re
from enum import Enum
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


class LogCategory(Enum):
    """日志分类"""
    SECURITY = "安全认证"
    SYSTEM = "系统核心"
    SERVICE = "服务应用"
    PACKAGE = "包管理"
    INSTALL = "安装部署"


class LogType(Enum):
    """日志类型"""
    # 第一阶段
    AUDIT = "audit"
    SECURE = "secure"
    AUTH = "auth"
    BTMP = "btmp"
    WTMP = "wtmp"
    LASTLOG = "lastlog"
    
    # 后续阶段
    MESSAGES = "messages"
    SYSLOG = "syslog"
    DMESG = "dmesg"
    BOOT = "boot"
    CRON = "cron"
    MAIL = "mail"
    FIREWALL = "firewall"
    YUM = "yum"
    DPKG = "dpkg"
    ANACONDA = "anaconda"


@dataclass
class LogTypeConfig:
    """日志类型配置"""
    name: str                    # 中文名称
    name_en: str                 # 英文名称
    description: str             # 描述
    category: LogCategory        # 分类
    format: str                  # 格式类型: syslog, audit, binary
    parser: str                  # 解析器名称
    file_patterns: List[str]     # 文件名正则模式
    priority: int = 2            # 优先级 1-3
    is_supported: bool = True    # BETA版本是否支持


# 支持的日志类型列表（BETA版本）
SUPPORTED_LOG_TYPES = ['audit', 'secure', 'auth', 'btmp', 'wtmp', 'lastlog']


# 日志类型配置表
LOG_TYPE_CONFIGS: Dict[LogType, LogTypeConfig] = {
    LogType.AUDIT: LogTypeConfig(
        name="审计日志",
        name_en="Audit Log",
        description="Linux内核审计子系统日志，记录系统安全相关事件",
        category=LogCategory.SECURITY,
        format="audit",
        parser="audit",
        file_patterns=[
            r'^audit\.log$',
            r'^audit\.log\.\d+$',
            r'^audit\.log\.\d+\.gz$',
            r'_audit\.log$',
            r'_audit\.log\.\d+$',
            r'_audit\.log\.\d+\.gz$',
            r'audit\.log',  # 通用匹配
        ],
        priority=3
    ),
    LogType.SECURE: LogTypeConfig(
        name="安全日志",
        name_en="Secure Log",
        description="SSH登录、sudo、PAM认证等安全相关日志(RHEL/CentOS)",
        category=LogCategory.SECURITY,
        format="syslog",
        parser="syslog",
        file_patterns=[
            r'^secure$',
            r'^secure-\d{8}$',
            r'^secure\.\d+$',
            r'^secure\.\d+\.gz$',
            r'_secure$',
            r'_secure-\d{8}$',
            r'_secure\.\d+$',
            r'varlog_secure',
        ],
        priority=3
    ),
    LogType.AUTH: LogTypeConfig(
        name="认证日志",
        name_en="Auth Log",
        description="系统认证日志(Debian/Ubuntu)",
        category=LogCategory.SECURITY,
        format="syslog",
        parser="syslog",
        file_patterns=[
            r'^auth\.log$',
            r'^auth\.log\.\d+$',
            r'^auth\.log\.\d+\.gz$',
            r'_auth\.log$',
            r'_auth\.log\.\d+$',
            r'auth\.log',  # 通用匹配
        ],
        priority=3
    ),
    LogType.BTMP: LogTypeConfig(
        name="失败登录",
        name_en="Bad Login",
        description="记录所有失败的登录尝试",
        category=LogCategory.SECURITY,
        format="binary",
        parser="utmp",
        file_patterns=[
            r'^btmp$',
            r'^btmp-\d{8}$',
            r'^btmp\.\d+$',
            r'_btmp$',
            r'_btmp-\d{8}$',
            r'_btmp\.\d+$',
        ],
        priority=2
    ),
    LogType.WTMP: LogTypeConfig(
        name="登录记录",
        name_en="Login Records",
        description="记录所有用户登录/登出",
        category=LogCategory.SECURITY,
        format="binary",
        parser="utmp",
        file_patterns=[
            r'^wtmp$',
            r'^wtmp-\d{8}$',
            r'^wtmp\.\d+$',
            r'_wtmp$',
            r'_wtmp-\d{8}$',
            r'_wtmp\.\d+$',
        ],
        priority=2
    ),
    LogType.LASTLOG: LogTypeConfig(
        name="最后登录",
        name_en="Last Login",
        description="记录每个用户最后一次登录",
        category=LogCategory.SECURITY,
        format="binary",
        parser="lastlog",
        file_patterns=[
            r'^lastlog$',
            r'_lastlog$',
            r'\.lastlog$',
        ],
        priority=2
    ),
    LogType.MESSAGES: LogTypeConfig(
        name="系统消息",
        name_en="Messages",
        description="通用系统日志消息",
        category=LogCategory.SYSTEM,
        format="syslog",
        parser="syslog",
        file_patterns=[
            r'^messages$',
            r'^messages-\d{8}$',
            r'^messages\.\d+$',
            r'_messages$',
            r'_messages-\d{8}$',
        ],
        priority=1,
        is_supported=False  # BETA版本不支持
    ),
    LogType.SYSLOG: LogTypeConfig(
        name="系统日志",
        name_en="Syslog",
        description="系统级日志信息",
        category=LogCategory.SYSTEM,
        format="syslog",
        parser="syslog",
        file_patterns=[
            r'^syslog$',
            r'^syslog\.\d+$',
            r'^syslog\.\d+\.gz$',
            r'_syslog$',
            r'_syslog\.\d+$',
            r'anaconda.*syslog',
        ],
        priority=1,
        is_supported=False  # BETA版本不支持
    ),
    LogType.CRON: LogTypeConfig(
        name="定时任务",
        name_en="Cron Log",
        description="Cron定时任务执行日志",
        category=LogCategory.SERVICE,
        format="syslog",
        parser="syslog",
        file_patterns=[
            r'^cron$',
            r'^cron-\d{8}$',
            r'^cron\.\d+$',
            r'_cron$',
            r'_cron-\d{8}$',
        ],
        priority=1,
        is_supported=False  # BETA版本不支持
    ),
}


def detect_log_type(filename: str) -> Optional[LogType]:
    """
    根据文件名检测日志类型
    
    Args:
        filename: 文件名(不含路径)
        
    Returns:
        日志类型，未识别返回None
    """
    # 提取基础文件名(去除路径前缀如 10.144.197.49+_log_)
    base_name = filename
    
    # 按优先级排序检测
    sorted_types = sorted(
        LOG_TYPE_CONFIGS.items(),
        key=lambda x: -x[1].priority
    )
    
    for log_type, config in sorted_types:
        for pattern in config.file_patterns:
            if re.search(pattern, base_name, re.IGNORECASE):
                return log_type
    
    return None


def get_log_type_config(log_type: LogType) -> LogTypeConfig:
    """获取日志类型配置"""
    return LOG_TYPE_CONFIGS.get(log_type)


def get_category_types(category: LogCategory) -> List[LogType]:
    """获取指定分类下的所有日志类型"""
    return [
        lt for lt, cfg in LOG_TYPE_CONFIGS.items()
        if cfg.category == category
    ]


def is_log_type_supported(log_type_str: str) -> bool:
    """检查日志类型是否在BETA版本中支持"""
    return log_type_str in SUPPORTED_LOG_TYPES


def get_log_type_info(log_type_str: str) -> Dict[str, Any]:
    """
    获取日志类型信息
    
    Returns:
        {
            "log_type": "messages",
            "name": "系统消息",
            "is_supported": False,
            "supported_types": ["audit", "secure", "auth", "btmp", "wtmp", "lastlog"]
        }
    """
    try:
        log_type = LogType(log_type_str)
        config = LOG_TYPE_CONFIGS.get(log_type)
        if config:
            return {
                "log_type": log_type_str,
                "name": config.name,
                "is_supported": config.is_supported,
                "supported_types": SUPPORTED_LOG_TYPES
            }
    except ValueError:
        pass
    
    return {
        "log_type": log_type_str,
        "name": log_type_str,
        "is_supported": log_type_str in SUPPORTED_LOG_TYPES,
        "supported_types": SUPPORTED_LOG_TYPES
    }
