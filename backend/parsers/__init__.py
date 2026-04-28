#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
日志解析器模块
"""

from .base_parser import BaseParser
from .audit_parser import AuditParser
from .syslog_parser import SyslogParser
from .utmp_parser import UtmpParser
from .lastlog_parser import LastlogParser

# 解析器注册表
PARSER_REGISTRY = {
    "audit": AuditParser,
    "syslog": SyslogParser,
    "utmp": UtmpParser,
    "lastlog": LastlogParser,
}


def get_parser(parser_name: str, log_type: str = "") -> BaseParser:
    """
    获取解析器实例
    
    Args:
        parser_name: 解析器名称
        log_type: 日志类型
        
    Returns:
        解析器实例
    """
    parser_class = PARSER_REGISTRY.get(parser_name)
    if parser_class:
        return parser_class(log_type)
    return None


__all__ = [
    'BaseParser',
    'AuditParser',
    'SyslogParser',
    'UtmpParser',
    'LastlogParser',
    'PARSER_REGISTRY',
    'get_parser',
]
