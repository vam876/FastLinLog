#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
解析器基类
"""

from abc import ABC, abstractmethod
from typing import Generator, Optional, List, Dict, Any
from pathlib import Path

from ..core.log_event import LogEvent


class BaseParser(ABC):
    """解析器基类"""
    
    name: str = "base"
    supported_types: List[str] = []
    
    def __init__(self, log_type: str = ""):
        self.log_type = log_type
        self._record_counter = 0
    
    @abstractmethod
    def parse_line(self, line: str, record_id: int = 0) -> Optional[LogEvent]:
        """解析单行日志"""
        pass
    
    def parse_file(self, file_path: str, encoding: str = 'utf-8') -> Generator[LogEvent, None, None]:
        """
        解析日志文件
        
        Args:
            file_path: 文件路径
            encoding: 文件编码
            
        Yields:
            LogEvent
        """
        path = Path(file_path)
        if not path.exists():
            return
        
        self._record_counter = 0
        
        # 尝试多种编码
        encodings = [encoding, 'utf-8', 'latin-1', 'gbk']
        
        for enc in encodings:
            try:
                with open(path, 'r', encoding=enc, errors='replace') as f:
                    for line in f:
                        line = line.rstrip('\n\r')
                        if not line.strip():
                            continue
                        
                        self._record_counter += 1
                        event = self.parse_line(line, self._record_counter)
                        if event:
                            event.log_type = self.log_type
                            event.raw_line = line
                            yield event
                break
            except UnicodeDecodeError:
                continue
            except Exception as e:
                print(f"解析文件错误 {file_path}: {e}")
                break
    
    def get_fields(self) -> List[Dict[str, str]]:
        """获取字段定义"""
        return [
            {"name": "record_id", "label": "记录ID", "type": "number"},
            {"name": "timestamp_str", "label": "时间", "type": "datetime"},
            {"name": "hostname", "label": "主机名", "type": "string"},
            {"name": "process", "label": "进程", "type": "string"},
            {"name": "pid", "label": "PID", "type": "number"},
            {"name": "user", "label": "用户", "type": "string"},
            {"name": "source_ip", "label": "来源IP", "type": "string"},
            {"name": "event_type", "label": "事件类型", "type": "string"},
            {"name": "event_name", "label": "事件名称", "type": "string"},
            {"name": "level", "label": "级别", "type": "string"},
            {"name": "result", "label": "结果", "type": "string"},
            {"name": "message", "label": "消息", "type": "string"},
        ]
