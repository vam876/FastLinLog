#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
UTMP二进制日志解析器
支持: btmp, wtmp
结构体大小: 384 bytes (Linux x86_64)
"""

import struct
from datetime import datetime
from typing import Optional, Generator
from pathlib import Path

from .base_parser import BaseParser
from ..core.log_event import LogEvent, EventLevel, EventResult


class UtmpParser(BaseParser):
    """UTMP/WTMP/BTMP二进制日志解析器"""
    
    name = "utmp"
    supported_types = ["btmp", "wtmp"]
    
    # 结构体常量
    UT_LINESIZE = 32
    UT_NAMESIZE = 32
    UT_HOSTSIZE = 256
    STRUCT_SIZE = 384  # Linux x86_64
    
    # 记录类型
    UT_TYPES = {
        0: ('EMPTY', '空记录', EventLevel.INFO),
        1: ('RUN_LVL', '运行级别变化', EventLevel.INFO),
        2: ('BOOT_TIME', '系统启动', EventLevel.INFO),
        3: ('NEW_TIME', '系统时间变化后', EventLevel.INFO),
        4: ('OLD_TIME', '系统时间变化前', EventLevel.INFO),
        5: ('INIT_PROCESS', 'Init进程', EventLevel.INFO),
        6: ('LOGIN_PROCESS', '登录进程', EventLevel.INFO),
        7: ('USER_PROCESS', '用户登录', EventLevel.INFO),
        8: ('DEAD_PROCESS', '进程终止', EventLevel.INFO),
        9: ('ACCOUNTING', '账户记录', EventLevel.INFO),
    }
    
    def parse_line(self, line: str, record_id: int = 0) -> Optional[LogEvent]:
        """不支持文本行解析"""
        return None
    
    def parse_file(self, file_path: str, encoding: str = None) -> Generator[LogEvent, None, None]:
        """
        解析二进制日志文件
        
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
        
        with open(path, 'rb') as f:
            while True:
                data = f.read(self.STRUCT_SIZE)
                if len(data) < self.STRUCT_SIZE:
                    break
                
                event = self._parse_record(data)
                if event and event.ut_type != 0:  # 跳过空记录
                    record_id += 1
                    event.record_id = record_id
                    event.log_type = self.log_type
                    yield event
    
    def _parse_record(self, data: bytes) -> Optional[LogEvent]:
        """解析单条记录"""
        try:
            # 解析结构体字段
            ut_type = struct.unpack('<h', data[0:2])[0]
            # padding 2 bytes
            ut_pid = struct.unpack('<i', data[4:8])[0]
            ut_line = data[8:8+self.UT_LINESIZE].rstrip(b'\x00').decode('utf-8', errors='replace')
            ut_id = data[40:44].rstrip(b'\x00').decode('utf-8', errors='replace')
            ut_user = data[44:44+self.UT_NAMESIZE].rstrip(b'\x00').decode('utf-8', errors='replace')
            ut_host = data[76:76+self.UT_HOSTSIZE].rstrip(b'\x00').decode('utf-8', errors='replace')
            
            # exit_status
            ut_exit_termination = struct.unpack('<h', data[332:334])[0]
            ut_exit_code = struct.unpack('<h', data[334:336])[0]
            
            # session id
            ut_session = struct.unpack('<i', data[336:340])[0]
            
            # timeval
            ut_tv_sec = struct.unpack('<i', data[340:344])[0]
            ut_tv_usec = struct.unpack('<i', data[344:348])[0]
            
            # IPv6 address (前4字节为IPv4)
            ut_addr_v6 = struct.unpack('<4I', data[348:364])
            
            # 转换IP地址
            ip_addr = ""
            if ut_addr_v6[0] != 0:
                ip_bytes = struct.pack('<I', ut_addr_v6[0])
                ip_addr = '.'.join(str(b) for b in ip_bytes)
            
            # 判断 ut_host 是否为IP地址
            host_is_ip = False
            if ut_host:
                # 检查是否是IPv4格式
                import re
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ut_host):
                    host_is_ip = True
            
            # 获取类型信息
            type_info = self.UT_TYPES.get(ut_type, ('UNKNOWN', f'未知类型({ut_type})', EventLevel.INFO))
            
            # 确定最终的IP地址和主机名
            final_ip = ip_addr if ip_addr else (ut_host if host_is_ip else '')
            final_hostname = '' if host_is_ip else ut_host
            
            # Create event
            event = LogEvent(
                ut_type=ut_type,
                ut_type_name=type_info[0],
                pid=ut_pid if ut_pid > 0 else None,
                line=ut_line,
                user=ut_user,
                hostname=final_hostname,
                source_ip=final_ip,
                session_id=ut_session if ut_session > 0 else None,
                event_type=type_info[0],
                event_name=type_info[1],
                level=type_info[2],
            )
            
            # Set time戳
            if ut_tv_sec > 0:
                event.set_timestamp(unix_ts=ut_tv_sec, usec=ut_tv_usec)
            
            # 设置事件分类和结果
            self._set_event_details(event, ut_type)
            
            # 额外数据
            event.extra = {
                'ut_id': ut_id,
                'exit_termination': ut_exit_termination,
                'exit_code': ut_exit_code,
            }
            
            # 构建消息
            event.message = self._build_message(event)
            
            return event
            
        except Exception as e:
            print(f"解析记录错误: {e}")
            return None
    
    def _set_event_details(self, event: LogEvent, ut_type: int):
        """设置事件详细信息"""
        from ..core.event_mappings import get_event_info
        
        # btmp 都是失败登录
        if self.log_type == 'btmp':
            info = get_event_info('BTMP_FAILED_LOGIN')
            if info:
                event.event_type = 'BTMP_FAILED_LOGIN'
                event.event_name = info.name
                event.event_category = info.category
                event.level = info.level
                event.result = info.result
            return
        
        # wtmp 根据类型设置
        event_type_map = {
            7: 'WTMP_LOGIN',      # USER_PROCESS - 登录
            8: 'WTMP_LOGOUT',     # DEAD_PROCESS - 登出
            2: 'UTMP_BOOT',       # BOOT_TIME
            1: 'UTMP_RUNLEVEL',   # RUN_LVL
            6: 'UTMP_LOGIN',      # LOGIN_PROCESS
            5: 'UTMP_BOOT',       # INIT_PROCESS
        }
        
        event_type = event_type_map.get(ut_type, 'UNKNOWN')
        info = get_event_info(event_type)
        if info:
            event.event_type = event_type
            event.event_name = info.name
            event.event_category = info.category
            event.level = info.level
            event.result = info.result
        else:
            event.event_category = '系统'
    
    def _build_message(self, event: LogEvent) -> str:
        """构建消息描述"""
        parts = []
        
        if event.user:
            parts.append(f"用户:{event.user}")
        if event.source_ip:
            parts.append(f"来源:{event.source_ip}")
        if event.line:
            parts.append(f"终端:{event.line}")
        if event.pid:
            parts.append(f"PID:{event.pid}")
        
        return ' | '.join(parts) if parts else event.event_name
    
    def get_fields(self):
        """获取utmp特有字段"""
        base = super().get_fields()
        utmp_fields = [
            {"name": "ut_type", "label": "记录类型码", "type": "number"},
            {"name": "ut_type_name", "label": "记录类型", "type": "string"},
            {"name": "line", "label": "终端", "type": "string"},
            {"name": "session_id", "label": "会话ID", "type": "number"},
        ]
        return base + utmp_fields
