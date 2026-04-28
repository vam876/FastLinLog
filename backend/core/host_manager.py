#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
主机管理器
识别和管理多主机日志
支持多种目录命名格式：
- 10.11.11.49 (纯IP)
- 10.11.11.49助记 (IP+中文备注)
- 10.11.11.49（测试） (IP+括号备注)
- 10.11.11.49_web (IP+下划线备注)
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from .log_types import LogType, LogCategory, detect_log_type, get_log_type_config


@dataclass
class HostInfo:
    """主机信息"""
    host_id: str                        # 主机ID (IP)
    host_type: str                      # ip, local
    display_name: str                   # 显示名称 (目录原名，含备注)
    directory: str                      # 目录路径
    total_files: int = 0
    total_size: int = 0


@dataclass
class LogFileInfo:
    """日志文件信息"""
    file_path: str
    file_name: str
    log_type: LogType
    host_id: str
    size: int = 0
    mtime: float = 0


@dataclass
class CategoryGroup:
    """分类组"""
    category: LogCategory
    log_types: Dict[LogType, List[LogFileInfo]] = field(default_factory=dict)
    
    @property
    def total_files(self) -> int:
        return sum(len(files) for files in self.log_types.values())

    @property
    def total_size(self) -> int:
        return sum(sum(f.size for f in files) for files in self.log_types.values())


class HostManager:
    """主机管理器 - 从目录名提取IP识别主机"""
    
    # 从目录名提取IP的正则 (支持各种后缀)
    IP_EXTRACT_PATTERN = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    
    def __init__(self, base_dir: str = "logs"):
        self._base_dir_str = str(base_dir)  # 保存字符串版本供外部访问
        self._base_dir = Path(base_dir)  # 内部使用的Path对象（私有）
        self.hosts: Dict[str, HostInfo] = {}
        self.files_by_host: Dict[str, List[LogFileInfo]] = defaultdict(list)
        self.categories_by_host: Dict[str, Dict[LogCategory, CategoryGroup]] = defaultdict(dict)
    
    @property
    def base_dir(self) -> Path:
        """获取基础目录Path对象（内部使用）"""
        return self._base_dir
    
    def get_base_dir(self) -> str:
        """获取基础目录路径（字符串）"""
        return self._base_dir_str
    
    def scan(self) -> Dict[str, HostInfo]:
        """扫描目录，识别主机和日志文件
        
        支持两种目录结构：
        1. 按主机分类: logs/10.144.197.49/secure/...
        2. 按日志类型分类: logs_classified/secure/10.144.197.49_secure
        """
        self.hosts.clear()
        self.files_by_host.clear()
        self.categories_by_host.clear()
        
        if not self.base_dir.exists():
            print(f"[HostManager] 目录不存在: {self.base_dir}")
            return {}
        
        # 检测目录结构类型
        first_level_dirs = [d for d in self.base_dir.iterdir() if d.is_dir()]
        
        # 判断是按主机还是按日志类型分类
        is_type_based = any(d.name.lower() in ('secure', 'auth', 'audit', 'syslog', 'messages', 
                                                'cron', 'boot', 'dmesg', 'btmp', 'wtmp', 'lastlog',
                                                'mail', 'firewall', 'yum', 'anaconda')
                           for d in first_level_dirs)
        
        if is_type_based:
            # 按日志类型分类的目录结构 (logs_classified)
            self._scan_type_based_directory()
        else:
            # 按主机分类的目录结构
            self._scan_host_based_directory()
        
        # Update statistics信息
        for host_id, file_list in self.files_by_host.items():
            if host_id in self.hosts:
                host = self.hosts[host_id]
                host.total_files = len(file_list)
                host.total_size = sum(f.size for f in file_list)
        
        print(f"[HostManager] 扫描完成: {len(self.hosts)}个主机, {sum(len(f) for f in self.files_by_host.values())}个文件")
        return self.hosts
    
    def _scan_type_based_directory(self):
        """扫描按日志类型分类的目录 (logs_classified/secure/...)"""
        # 用于跟踪是否有多个主机
        all_host_ids = set()
        skipped_files = []  # 记录跳过的文件
        
        for type_dir in self.base_dir.iterdir():
            if not type_dir.is_dir():
                continue
            
            # 从目录名推断日志类型
            log_type = self._detect_from_directory(type_dir.name)
            
            # 扫描该类型目录下的所有文件
            for filepath in type_dir.iterdir():
                if filepath.is_dir():
                    continue
                
                filename = filepath.name
                
                # 跳过非日志文件（脚本、配置等）
                if filename.endswith(('.sh', '.py', '.xml', '.conf', '.cfg')):
                    continue
                
                # 从文件名提取主机ID
                host_id = self._extract_host_from_filename(filename)
                if host_id:
                    all_host_ids.add(host_id)
                
                # Process file - 优先使用目录推断的类型，其次使用文件名检测
                actual_log_type = log_type or detect_log_type(filename)
                
                # 如果仍然无法识别，尝试从目录名强制推断
                if not actual_log_type and log_type is None:
                    # 根据目录名尝试匹配
                    dir_name_lower = type_dir.name.lower()
                    if 'audit' in dir_name_lower:
                        actual_log_type = LogType.AUDIT
                    elif 'secure' in dir_name_lower:
                        actual_log_type = LogType.SECURE
                    elif 'auth' in dir_name_lower:
                        actual_log_type = LogType.AUTH
                    elif 'btmp' in dir_name_lower:
                        actual_log_type = LogType.BTMP
                    elif 'wtmp' in dir_name_lower:
                        actual_log_type = LogType.WTMP
                    elif 'cron' in dir_name_lower:
                        actual_log_type = LogType.CRON
                    elif 'message' in dir_name_lower:
                        actual_log_type = LogType.MESSAGES
                    elif 'syslog' in dir_name_lower:
                        actual_log_type = LogType.SYSLOG
                
                if actual_log_type:
                    self._add_file_temp(str(filepath), filename, actual_log_type, host_id)
                else:
                    skipped_files.append(filename)
        
        if skipped_files:
            print(f"[HostManager] 跳过 {len(skipped_files)} 个无法识别的文件")
            if len(skipped_files) <= 10:
                for f in skipped_files:
                    print(f"  - {f}")
        
        # 判断是否需要按主机分组
        # 如果只有一个或没有主机，就不按主机分组
        use_host_grouping = len(all_host_ids) > 1
        
        if not use_host_grouping:
            # 不按主机分组，所有文件归入 "all" 组
            default_host = "all"
            self.hosts[default_host] = HostInfo(
                host_id=default_host,
                host_type="all",
                display_name="所有日志",
                directory=str(self.base_dir)
            )
            
            # 合并所有文件到默认组
            all_files = []
            for files in self._temp_files.values():
                all_files.extend(files)
            
            for file_info in all_files:
                file_info.host_id = default_host
                self.files_by_host[default_host].append(file_info)
                
                config = get_log_type_config(file_info.log_type)
                if config:
                    category = config.category
                    if category not in self.categories_by_host[default_host]:
                        self.categories_by_host[default_host][category] = CategoryGroup(category=category)
                    
                    cat_group = self.categories_by_host[default_host][category]
                    if file_info.log_type not in cat_group.log_types:
                        cat_group.log_types[file_info.log_type] = []
                    cat_group.log_types[file_info.log_type].append(file_info)
        else:
            # 按主机分组
            for host_id, files in self._temp_files.items():
                actual_host_id = host_id or "local"
                
                if actual_host_id not in self.hosts:
                    display_name = actual_host_id if actual_host_id != "local" else "本机日志"
                    self.hosts[actual_host_id] = HostInfo(
                        host_id=actual_host_id,
                        host_type="ip" if actual_host_id not in ("local", "all") else actual_host_id,
                        display_name=display_name,
                        directory=str(self.base_dir)
                    )
                
                for file_info in files:
                    file_info.host_id = actual_host_id
                    self.files_by_host[actual_host_id].append(file_info)
                    
                    config = get_log_type_config(file_info.log_type)
                    if config:
                        category = config.category
                        if category not in self.categories_by_host[actual_host_id]:
                            self.categories_by_host[actual_host_id][category] = CategoryGroup(category=category)
                        
                        cat_group = self.categories_by_host[actual_host_id][category]
                        if file_info.log_type not in cat_group.log_types:
                            cat_group.log_types[file_info.log_type] = []
                        cat_group.log_types[file_info.log_type].append(file_info)
        
        # 清理临时数据
        self._temp_files.clear()
    
    def _add_file_temp(self, filepath: str, filename: str, log_type: LogType, host_id: Optional[str]):
        """临时添加文件（用于判断是否需要主机分组）"""
        if not hasattr(self, '_temp_files'):
            self._temp_files = defaultdict(list)
        
        try:
            size = os.path.getsize(filepath)
            mtime = os.path.getmtime(filepath)
        except:
            size, mtime = 0, 0
        
        file_info = LogFileInfo(
            file_path=filepath,
            file_name=filename,
            log_type=log_type,
            host_id=host_id or "unknown",
            size=size,
            mtime=mtime
        )
        
        self._temp_files[host_id].append(file_info)
    
    def _scan_host_based_directory(self):
        """扫描按主机分类的目录"""
        for item in self.base_dir.iterdir():
            if not item.is_dir():
                continue
            
            dir_name = item.name
            host_id, host_type, display_name = self._identify_host_from_dir(dir_name)
            
            if not host_id:
                print(f"[HostManager] 跳过无法识别的目录: {dir_name}")
                continue
            
            if host_id not in self.hosts:
                self.hosts[host_id] = HostInfo(
                    host_id=host_id,
                    host_type=host_type,
                    display_name=display_name,
                    directory=str(item)
                )
            
            self._scan_host_directory(item, host_id)
    
    def _extract_host_from_filename(self, filename: str) -> Optional[str]:
        """从文件名提取主机ID"""
        # 尝试从文件名提取IP
        ip_match = self.IP_EXTRACT_PATTERN.search(filename)
        if ip_match:
            ip = ip_match.group(1)
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                return ip
        
        # 检查是否有主机名前缀 (如 linux-log-0511-86_log_secure)
        if filename.startswith('linux-log-'):
            parts = filename.split('_')
            if parts:
                return parts[0]
        
        # 没有主机标识，返回 None（将归入默认组）
        return None
    
    def _extract_log_group_key(self, filename: str) -> str:
        """
        从文件名提取日志分组键
        用于将相似的日志文件聚合在一起
        
        例如:
        - auth.log, auth.log.1, auth.log.2.gz -> auth
        - secure, secure-20231201 -> secure
        - messages, messages-20231201 -> messages
        """
        import re
        
        # 移除常见后缀
        name = filename
        
        # 移除 .gz, .bz2, .xz 压缩后缀
        name = re.sub(r'\.(gz|bz2|xz|zip)$', '', name, flags=re.IGNORECASE)
        
        # 移除数字后缀 (.1, .2, -20231201 等)
        name = re.sub(r'[\.-]\d+$', '', name)
        name = re.sub(r'-\d{8}$', '', name)  # 日期格式
        
        # 移除 .log 后缀
        name = re.sub(r'\.log$', '', name, flags=re.IGNORECASE)
        
        # 提取基础名称（去除路径前缀如 varlog_, 10.144.197.49+_log_ 等）
        # 匹配 IP+路径 前缀
        name = re.sub(r'^\d+\.\d+\.\d+\.\d+\+?_[^_]+_', '', name)
        # 匹配 varlog_ 前缀
        name = re.sub(r'^varlog_', '', name)
        # 匹配其他路径前缀
        name = re.sub(r'^[^_]+_log_', '', name)
        
        return name.lower() if name else filename.lower()
    
    def _add_file(self, filepath: str, filename: str, log_type: LogType, host_id: str):
        """添加文件到管理器"""
        try:
            size = os.path.getsize(filepath)
            mtime = os.path.getmtime(filepath)
        except:
            size, mtime = 0, 0
        
        file_info = LogFileInfo(
            file_path=filepath,
            file_name=filename,
            log_type=log_type,
            host_id=host_id,
            size=size,
            mtime=mtime
        )
        
        self.files_by_host[host_id].append(file_info)
        
        config = get_log_type_config(log_type)
        if config:
            category = config.category
            if category not in self.categories_by_host[host_id]:
                self.categories_by_host[host_id][category] = CategoryGroup(category=category)
            
            cat_group = self.categories_by_host[host_id][category]
            if log_type not in cat_group.log_types:
                cat_group.log_types[log_type] = []
            cat_group.log_types[log_type].append(file_info)
    
    def _identify_host_from_dir(self, dir_name: str) -> Tuple[Optional[str], str, str]:
        """从目录名识别主机"""
        # 尝试提取IP
        ip_match = self.IP_EXTRACT_PATTERN.search(dir_name)
        if ip_match:
            ip = ip_match.group(1)
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                return ip, "ip", dir_name
        
        # 本地日志目录
        lower_name = dir_name.lower()
        if lower_name in ('local', 'localhost', '本地', '本机'):
            return "local", "local", "本机日志"
        
        return None, "", ""
    
    def _scan_host_directory(self, host_dir: Path, host_id: str):
        """扫描主机目录下的日志文件"""
        for root, dirs, files in os.walk(host_dir):
            for filename in files:
                filepath = os.path.join(root, filename)
                self._process_file(filepath, filename, host_id)
    
    def _process_file(self, filepath: str, filename: str, host_id: str):
        """处理单个文件"""
        log_type = detect_log_type(filename)
        if not log_type:
            parent_dir = os.path.basename(os.path.dirname(filepath))
            log_type = self._detect_from_directory(parent_dir)
        
        if not log_type:
            return
        
        try:
            size = os.path.getsize(filepath)
            mtime = os.path.getmtime(filepath)
        except:
            size, mtime = 0, 0
        
        file_info = LogFileInfo(
            file_path=filepath,
            file_name=filename,
            log_type=log_type,
            host_id=host_id,
            size=size,
            mtime=mtime
        )
        
        self.files_by_host[host_id].append(file_info)
        
        config = get_log_type_config(log_type)
        if config:
            category = config.category
            if category not in self.categories_by_host[host_id]:
                self.categories_by_host[host_id][category] = CategoryGroup(category=category)
            
            cat_group = self.categories_by_host[host_id][category]
            if log_type not in cat_group.log_types:
                cat_group.log_types[log_type] = []
            cat_group.log_types[log_type].append(file_info)
    
    def _detect_from_directory(self, dir_name: str) -> Optional[LogType]:
        """从目录名推断日志类型"""
        mapping = {
            'audit': LogType.AUDIT, 'secure': LogType.SECURE,
            'auth': LogType.AUTH, 'btmp': LogType.BTMP,
            'wtmp': LogType.WTMP, 'lastlog': LogType.LASTLOG,
        }
        return mapping.get(dir_name.lower())

    def get_host_tree(self) -> List[dict]:
        """获取主机树形结构"""
        tree = []
        for host_id, host in self.hosts.items():
            host_node = {
                "host_id": host.host_id,
                "host_type": host.host_type,
                "display_name": host.display_name,
                "total_files": host.total_files,
                "total_size": host.total_size,
                "categories": []
            }
            
            if host_id in self.categories_by_host:
                for category, cat_group in self.categories_by_host[host_id].items():
                    cat_node = {
                        "category_id": category.value,
                        "category_name": category.value,
                        "total_files": cat_group.total_files,
                        "log_types": []
                    }
                    
                    for log_type, files in cat_group.log_types.items():
                        config = get_log_type_config(log_type)
                        type_node = {
                            "type_id": log_type.value,
                            "type_name": config.name if config else log_type.value,
                            "file_count": len(files),
                            "files": [{"file_name": f.file_name, "file_path": f.file_path, "size": f.size}
                                      for f in sorted(files, key=lambda x: x.file_name)]
                        }
                        cat_node["log_types"].append(type_node)
                    host_node["categories"].append(cat_node)
            tree.append(host_node)
        
        tree.sort(key=lambda x: (x["host_type"] != "ip", x["host_id"]))
        return tree
    
    def get_files_by_host_and_type(self, host_id: str, log_type: str) -> List[LogFileInfo]:
        """获取指定主机和类型的文件列表"""
        try:
            lt = LogType(log_type)
        except:
            return []
        if host_id not in self.files_by_host:
            return []
        return [f for f in self.files_by_host[host_id] if f.log_type == lt]
    
    def get_summary(self) -> dict:
        """获取扫描摘要"""
        return {
            "total_hosts": len(self.hosts),
            "total_files": sum(h.total_files for h in self.hosts.values()),
            "total_size": sum(h.total_size for h in self.hosts.values()),
            "hosts": [
                {"host_id": h.host_id, "host_type": h.host_type, 
                 "display_name": h.display_name, "total_files": h.total_files}
                for h in self.hosts.values()
            ]
        }
