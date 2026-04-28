#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Lastlog二进制日志解析器
记录每个用户最后一次登录
结构体大小: 292 bytes
按UID顺序存储
"""

import struct
from datetime import datetime
from typing import Optional, Generator
from pathlib import Path

from .base_parser import BaseParser
from ..core.log_event import LogEvent, EventLevel, EventResult


class LastlogParser(BaseParser):
    """Lastlog二进制日志解析器"""
    
    name = "lastlog"
    supported_types = ["lastlog"]
    
    # 结构体常量
    UT_LINESIZE = 32
    UT_HOSTSIZE = 256
    STRUCT_SIZE = 4 + 32 + 256  # 292 bytes
    
    def parse_line(self, line: str, record_id: int = 0) -> Optional[LogEvent]:
        """不支持文本行解析"""
        return None
    
    def parse_file(self, file_path: str, encoding: str = None) -> Generator[LogEvent, None, None]:
        """
        解析lastlog文件
        
        Args:
            file_path: 文件路径
            encoding: 忽略(二进制文件)
            
        Yields:
            LogEvent
        """
        path = Path(file_path)
        if not path.exists():
            return
        
        record_id = 0
        uid = 0
        
        with open(path, 'rb') as f:
            while True:
                data = f.read(self.STRUCT_SIZE)
                if len(data) < self.STRUCT_SIZE:
                    break
                
                event = self._parse_record(data, uid)
                uid += 1
                
                if event:  # 只返回有登录记录的
                    record_id += 1
                    event.record_id = record_id
                    event.log_type = self.log_type
                    yield event
    
    def _parse_record(self, data: bytes, uid: int) -> Optional[LogEvent]:
        """解析单条记录"""
        try:
            # 解析结构体
            ll_time = struct.unpack('<i', data[0:4])[0]
            ll_line = data[4:4+self.UT_LINESIZE].rstrip(b'\x00').decode('utf-8', errors='replace')
            ll_host = data[36:36+self.UT_HOSTSIZE].rstrip(b'\x00').decode('utf-8', errors='replace')
            
            # 跳过没有登录记录的
            if ll_time <= 0:
                return None
            
            # 尝试获取用户名
            username = self._get_username_by_uid(uid)
            
            # 从事件映射获取信息
            from ..core.event_mappings import get_event_info
            info = get_event_info('LASTLOG_ENTRY')
            
            # Create event
            event = LogEvent(
                uid=uid,
                user=username,  # 设置用户名
                line=ll_line,
                source_ip=ll_host,
                hostname=ll_host if not self._is_ip(ll_host) else '',
                event_type='LASTLOG_ENTRY',
                event_name=info.name if info else '最后登录',
                event_category=info.category if info else '认证',
                level=info.level if info else EventLevel.INFO,
                result=info.result if info else EventResult.SUCCESS,
            )
            
            # Set time戳
            event.set_timestamp(unix_ts=ll_time)
            
            # 构建消息
            event.message = f"用户:{username} (UID:{uid}) | 终端:{ll_line} | 来源:{ll_host}"
            
            # 额外数据
            event.extra = {
                'uid': uid,
                'username': username,
            }
            
            return event
            
        except Exception as e:
            print(f"解析lastlog记录错误 (UID={uid}): {e}")
            return None
    
    def _get_username_by_uid(self, uid: int) -> str:
        """根据UID获取用户名"""
        # 常见系统用户映射
        common_users = {
            0: 'root',
            1: 'bin',
            2: 'daemon',
            3: 'adm',
            4: 'lp',
            5: 'sync',
            6: 'shutdown',
            7: 'halt',
            8: 'mail',
            11: 'operator',
            12: 'games',
            14: 'ftp',
            65534: 'nobody',
            65533: 'nogroup',
        }
        return common_users.get(uid, f'user_{uid}')
    
    def _is_ip(self, s: str) -> bool:
        """判断是否为IP地址"""
        import re
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s))
    
    def get_fields(self):
        """获取lastlog特有字段"""
        return [
            {"name": "record_id", "label": "记录ID", "type": "number"},
            {"name": "timestamp_str", "label": "最后登录时间", "type": "datetime"},
            {"name": "uid", "label": "UID", "type": "number"},
            {"name": "line", "label": "终端", "type": "string"},
            {"name": "source_ip", "label": "来源", "type": "string"},
            {"name": "event_name", "label": "事件", "type": "string"},
        ]
