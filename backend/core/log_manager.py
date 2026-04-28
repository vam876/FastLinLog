#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
日志管理器
负责扫描目录、识别日志类型、聚合同类文件
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Generator, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict

from .log_types import LogType, LogCategory, LOG_TYPE_CONFIGS, detect_log_type, get_log_type_config
from .log_event import LogEvent


@dataclass
class LogFileInfo:
    """日志文件信息"""
    path: str                           # 完整路径
    filename: str                       # 文件名
    log_type: LogType                   # 日志类型
    size: int = 0                       # 文件大小
    group_key: str = ""                 # 聚合分组键
    
    def __post_init__(self):
        if os.path.exists(self.path):
            self.size = os.path.getsize(self.path)


@dataclass
class LogFileGroup:
    """日志文件组(聚合同类文件)"""
    group_key: str                      # 分组键
    log_type: LogType                   # 日志类型
    files: List[LogFileInfo] = field(default_factory=list)
    total_size: int = 0                 # 总大小
    
    @property
    def type_name(self) -> str:
        config = get_log_type_config(self.log_type)
        return config.name if config else self.log_type.value
    
    @property
    def file_count(self) -> int:
        return len(self.files)
    
    def add_file(self, file_info: LogFileInfo):
        self.files.append(file_info)
        self.total_size += file_info.size
    
    def get_sorted_files(self) -> List[LogFileInfo]:
        """按文件名排序(确保时间顺序)"""
        return sorted(self.files, key=lambda f: f.filename)


class LogManager:
    """日志管理器"""
    
    def __init__(self, base_dir: str = "logs"):
        """
        初始化日志管理器
        
        Args:
            base_dir: 日志根目录
        """
        self._base_dir_str = str(base_dir)  # 保存字符串版本供外部访问
        self._base_dir = Path(base_dir)  # 内部使用的Path对象（私有）
        self.file_groups: Dict[str, LogFileGroup] = {}
        self.files_by_type: Dict[LogType, List[LogFileInfo]] = defaultdict(list)
        self._parsers = {}
    
    @property
    def base_dir(self) -> Path:
        """获取基础目录Path对象（内部使用）"""
        return self._base_dir
    
    def get_base_dir(self) -> str:
        """获取基础目录路径（字符串）"""
        return self._base_dir_str
    
    def scan_directory(self, directory: str = None) -> Dict[str, LogFileGroup]:
        """
        扫描目录，识别并聚合日志文件
        
        Args:
            directory: 要扫描的目录，默认为base_dir
            
        Returns:
            文件组字典 {group_key: LogFileGroup}
        """
        scan_dir = Path(directory) if directory else self.base_dir
        
        if not scan_dir.exists():
            print(f"目录不存在: {scan_dir}")
            return {}
        
        self.file_groups.clear()
        self.files_by_type.clear()
        
        # 递归扫描所有文件
        for root, dirs, files in os.walk(scan_dir):
            for filename in files:
                filepath = os.path.join(root, filename)
                self._process_file(filepath, filename, root)
        
        return self.file_groups
    
    def _process_file(self, filepath: str, filename: str, directory: str):
        """处理单个文件"""
        # 检测日志类型
        log_type = detect_log_type(filename)
        if not log_type:
            # 尝试从目录名推断
            log_type = self._detect_from_directory(directory)
        
        if not log_type:
            return
        
        # 创建文件信息
        file_info = LogFileInfo(
            path=filepath,
            filename=filename,
            log_type=log_type
        )
        
        # 生成分组键
        group_key = self._generate_group_key(filepath, filename, log_type, directory)
        file_info.group_key = group_key
        
        # 添加到分组
        if group_key not in self.file_groups:
            self.file_groups[group_key] = LogFileGroup(
                group_key=group_key,
                log_type=log_type
            )
        
        self.file_groups[group_key].add_file(file_info)
        self.files_by_type[log_type].append(file_info)
    
    def _detect_from_directory(self, directory: str) -> Optional[LogType]:
        """从目录名推断日志类型"""
        dir_name = os.path.basename(directory).lower()
        
        type_mapping = {
            'audit': LogType.AUDIT,
            'secure': LogType.SECURE,
            'auth': LogType.AUTH,
            'btmp': LogType.BTMP,
            'wtmp': LogType.WTMP,
            'lastlog': LogType.LASTLOG,
        }
        
        return type_mapping.get(dir_name)
    
    def _generate_group_key(self, filepath: str, filename: str, 
                           log_type: LogType, directory: str) -> str:
        """
        生成分组键
        同一来源的同类型日志聚合在一起
        
        例如:
        - 10.144.197.49+_log_audit_audit.log
        - 10.144.197.49+_log_audit_audit.log.1
        聚合为: 10.144.197.49+_audit
        """
        # 提取来源标识(IP或主机名前缀)
        source_prefix = ""
        
        # 匹配 IP+前缀 格式: 10.144.197.49+_
        ip_match = re.match(r'^([\d.]+\+?)_', filename)
        if ip_match:
            source_prefix = ip_match.group(1)
        else:
            # 匹配 主机名前缀 格式: linux-log-0511-86_
            host_match = re.match(r'^([a-zA-Z0-9-]+)_', filename)
            if host_match:
                source_prefix = host_match.group(1)
            else:
                # 使用目录名作为来源
                source_prefix = os.path.basename(directory)
        
        return f"{source_prefix}_{log_type.value}"
    
    def get_groups_by_category(self) -> Dict[LogCategory, List[LogFileGroup]]:
        """按分类获取文件组"""
        result = defaultdict(list)
        
        for group in self.file_groups.values():
            config = get_log_type_config(group.log_type)
            if config:
                result[config.category].append(group)
        
        return dict(result)
    
    def get_groups_by_type(self, log_type: LogType) -> List[LogFileGroup]:
        """获取指定类型的所有文件组"""
        return [g for g in self.file_groups.values() if g.log_type == log_type]
    
    def get_parser(self, log_type: LogType):
        """获取解析器实例"""
        if log_type not in self._parsers:
            from ..parsers import get_parser
            config = get_log_type_config(log_type)
            if config:
                self._parsers[log_type] = get_parser(config.parser, log_type.value)
        return self._parsers.get(log_type)
    
    def parse_group(self, group: LogFileGroup) -> Generator[LogEvent, None, None]:
        """
        解析文件组中的所有文件
        
        Args:
            group: 文件组
            
        Yields:
            LogEvent
        """
        parser = self.get_parser(group.log_type)
        if not parser:
            print(f"未找到解析器: {group.log_type}")
            return
        
        record_id = 0
        for file_info in group.get_sorted_files():
            for event in parser.parse_file(file_info.path):
                record_id += 1
                event.record_id = record_id
                event.source_file = file_info.filename
                yield event
    
    def parse_group_paginated(self, group: LogFileGroup, 
                              page: int = 1, 
                              page_size: int = 100) -> Dict[str, Any]:
        """
        分页解析文件组
        
        Args:
            group: 文件组
            page: 页码(从1开始)
            page_size: 每页大小
            
        Returns:
            {events: [...], pagination: {...}}
        """
        events = []
        total_count = 0
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        
        for idx, event in enumerate(self.parse_group(group)):
            total_count = idx + 1
            if start_idx <= idx < end_idx:
                events.append(event.to_dict())
        
        total_pages = (total_count + page_size - 1) // page_size if total_count > 0 else 1
        
        return {
            "events": events,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_count": total_count,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_prev": page > 1
            }
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """获取扫描摘要"""
        summary = {
            "total_groups": len(self.file_groups),
            "total_files": sum(g.file_count for g in self.file_groups.values()),
            "total_size": sum(g.total_size for g in self.file_groups.values()),
            "by_category": {},
            "by_type": {},
        }
        
        # 按分类统计
        for category, groups in self.get_groups_by_category().items():
            summary["by_category"][category.value] = {
                "groups": len(groups),
                "files": sum(g.file_count for g in groups),
                "size": sum(g.total_size for g in groups),
            }
        
        # 按类型统计
        for log_type, files in self.files_by_type.items():
            config = get_log_type_config(log_type)
            summary["by_type"][log_type.value] = {
                "name": config.name if config else log_type.value,
                "files": len(files),
                "size": sum(f.size for f in files),
            }
        
        return summary
    
    def print_summary(self):
        """打印扫描摘要"""
        summary = self.get_summary()
        
        print(f"\n{'='*60}")
        print(f"日志扫描摘要")
        print(f"{'='*60}")
        print(f"总文件组: {summary['total_groups']}")
        print(f"总文件数: {summary['total_files']}")
        print(f"总大小: {summary['total_size'] / 1024 / 1024:.2f} MB")
        
        print(f"\n按分类统计:")
        for cat, stats in summary["by_category"].items():
            print(f"  {cat}: {stats['groups']}组, {stats['files']}文件, {stats['size']/1024/1024:.2f}MB")
        
        print(f"\n按类型统计:")
        for type_name, stats in summary["by_type"].items():
            print(f"  {stats['name']}({type_name}): {stats['files']}文件, {stats['size']/1024/1024:.2f}MB")
        
        print(f"\n文件组详情:")
        for group_key, group in sorted(self.file_groups.items()):
            print(f"  [{group.type_name}] {group_key}: {group.file_count}文件, {group.total_size/1024:.1f}KB")
