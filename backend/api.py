#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Linux日志分析API
提供给前端调用的接口
支持多主机分区和SQLite缓存
"""

import os
import sys
from typing import Dict, List, Any, Optional
from pathlib import Path

from .core.log_types import LogType, LogCategory, LOG_TYPE_CONFIGS, get_log_type_config
from .core.log_manager import LogManager, LogFileGroup
from .core.host_manager import HostManager, HostInfo, LogFileInfo, CategoryGroup
from .core.cache_manager import LinuxLogCacheManager


class LinuxLogAPI:
    """Linux日志分析API - 支持多主机和缓存"""
    
    def __init__(self, base_dir: str = "logs"):
        # Get base directory
        if getattr(sys, 'frozen', False):
            self._base_path = os.path.dirname(sys.executable)
        else:
            self._base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        self.base_dir = os.path.join(self._base_path, base_dir)
        self.manager = LogManager(self.base_dir)
        self.host_manager = HostManager(self.base_dir)
        self.cache_manager = LinuxLogCacheManager()
        self._scanned = False
        self._use_host_mode = False  # 是否使用主机模式
        
        print(f"[LinuxLogAPI] 初始化完成, 日志目录: {self.base_dir}")
    
    def scan(self, directory: str = None) -> Dict[str, Any]:
        """
        扫描日志目录
        
        Args:
            directory: 要扫描的目录
            
        Returns:
            扫描摘要
        """
        scan_dir = directory or self.base_dir
        
        # 扫描主机
        self.host_manager = HostManager(scan_dir)
        hosts = self.host_manager.scan()
        
        # 判断是否使用主机模式 (有多个主机或有IP命名的主机)
        self._use_host_mode = len(hosts) > 1 or any(h.host_type == "ip" for h in hosts.values())
        
        # 同时扫描传统模式
        self.manager.scan_directory(scan_dir)
        self._scanned = True
        
        print(f"[LinuxLogAPI] 扫描完成: {len(hosts)}个主机, 主机模式={self._use_host_mode}")
        
        return self.get_summary()
    
    def get_summary(self) -> Dict[str, Any]:
        """获取扫描摘要"""
        if not self._scanned:
            self.scan()
        
        summary = self.manager.get_summary()
        
        # 添加主机信息
        host_summary = self.host_manager.get_summary()
        summary["hosts"] = host_summary.get("hosts", [])
        summary["total_hosts"] = host_summary.get("total_hosts", 0)
        summary["use_host_mode"] = self._use_host_mode
        
        return summary
    
    # ================= 主机管理API =================
    
    def get_hosts(self) -> Dict[str, Any]:
        """
        获取所有主机列表
        
        Returns:
            {
                "success": True,
                "hosts": [...],
                "use_host_mode": True/False
            }
        """
        if not self._scanned:
            self.scan()
        
        try:
            summary = self.host_manager.get_summary()
            return {
                "success": True,
                "hosts": summary.get("hosts", []),
                "total_hosts": summary.get("total_hosts", 0),
                "total_files": summary.get("total_files", 0),
                "total_size": summary.get("total_size", 0),
                "use_host_mode": self._use_host_mode
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_host_tree(self) -> Dict[str, Any]:
        """
        获取主机树形结构 (用于侧边栏)
        
        Returns:
            {
                "success": True,
                "tree": [
                    {
                        "host_id": "10.144.197.49",
                        "host_type": "ip",
                        "display_name": "10.144.197.49",
                        "categories": [...]
                    }
                ],
                "use_host_mode": True/False
            }
        """
        if not self._scanned:
            self.scan()
        
        try:
            tree = self.host_manager.get_host_tree()
            return {
                "success": True,
                "tree": tree,
                "use_host_mode": self._use_host_mode
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ================= 缓存事件加载API =================
    
    def load_events_cached(self, host_id: str, log_type: str,
                           page: int = 1, page_size: int = 100,
                           sort_field: str = "timestamp_unix",
                           sort_direction: str = "desc",
                           filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        从缓存加载事件 (优先使用缓存)
        
        Args:
            host_id: 主机ID
            log_type: 日志类型
            page: 页码
            page_size: 每页大小
            sort_field: 排序字段
            sort_direction: 排序方向
            filters: 筛选条件
            
        Returns:
            {
                "success": True,
                "events": [...],
                "pagination": {...},
                "from_cache": True/False
            }
        """
        if not self._scanned:
            self.scan()
        
        try:
            # 检查日志类型是否在BETA版本中支持
            from .core.log_types import is_log_type_supported, get_log_type_info, SUPPORTED_LOG_TYPES
            if not is_log_type_supported(log_type):
                type_info = get_log_type_info(log_type)
                return {
                    "success": False,
                    "error": f"BETA版本暂不支持此日志类型: {type_info.get('name', log_type)}",
                    "log_type": log_type,
                    "is_supported": False,
                    "supported_types": SUPPORTED_LOG_TYPES
                }
            
            # 获取该主机和类型的文件列表
            files = self.host_manager.get_files_by_host_and_type(host_id, log_type)
            
            if not files:
                return {
                    "success": True,
                    "events": [],
                    "pagination": {"page": 1, "page_size": page_size, "total_count": 0, "total_pages": 0},
                    "from_cache": False,
                    "message": "没有找到匹配的日志文件"
                }
            
            # Check cache是否有效，如果无效则重新缓存
            need_cache = []
            for file_info in files:
                if not self.cache_manager.is_cache_valid(file_info.file_path):
                    need_cache.append(file_info)
            
            # 缓存新文件
            if need_cache:
                print(f"[LinuxLogAPI] 需要缓存 {len(need_cache)} 个文件")
                for file_info in need_cache:
                    self._cache_file(file_info, host_id)
            
            # 从缓存加载
            result = self.cache_manager.load_events(
                log_type=log_type,
                host_id=host_id,
                page=page,
                page_size=page_size,
                sort_field=sort_field,
                sort_direction=sort_direction,
                filters=filters
            )
            
            return result
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def _cache_file(self, file_info: LogFileInfo, host_id: str):
        """缓存单个文件"""
        try:
            # 检查日志类型是否在BETA版本中支持
            from .core.log_types import is_log_type_supported
            log_type_str = file_info.log_type.value if hasattr(file_info.log_type, 'value') else str(file_info.log_type)
            
            if not is_log_type_supported(log_type_str):
                print(f"[LinuxLogAPI] 跳过不支持的日志类型: {log_type_str} ({file_info.file_name})")
                return
            
            parser = self.manager.get_parser(file_info.log_type)
            if not parser:
                print(f"[LinuxLogAPI] 没有找到解析器: {file_info.log_type}")
                return
            
            # 设置源文件路径，让解析器使用正确的年份
            if hasattr(parser, 'set_source_file'):
                parser.set_source_file(file_info.file_path)
                print(f"[LinuxLogAPI] 设置解析器年份: {parser.get_year_info() if hasattr(parser, 'get_year_info') else 'N/A'}")
            
            # 解析并缓存
            events = parser.parse_file(file_info.file_path)
            self.cache_manager.cache_events(
                file_path=file_info.file_path,
                log_type=file_info.log_type.value,
                host_id=host_id,
                events=events
            )
        except Exception as e:
            print(f"[LinuxLogAPI] 缓存文件失败 {file_info.file_path}: {e}")
    
    def refresh_cache(self, host_id: str = None, log_type: str = None) -> Dict[str, Any]:
        """
        刷新缓存
        
        Args:
            host_id: 主机ID (可选，不指定则刷新所有)
            log_type: 日志类型 (可选)
            
        Returns:
            刷新结果
        """
        if not self._scanned:
            self.scan()
        
        try:
            # 清除旧缓存
            self.cache_manager.clear_cache(log_type=log_type, host_id=host_id)
            
            # 重新缓存
            cached_count = 0
            for hid, files in self.host_manager.files_by_host.items():
                if host_id and hid != host_id:
                    continue
                
                for file_info in files:
                    if log_type:
                        try:
                            lt = LogType(log_type)
                            if file_info.log_type != lt:
                                continue
                        except:
                            continue
                    
                    self._cache_file(file_info, hid)
                    cached_count += 1
            
            return {
                "success": True,
                "cached_files": cached_count,
                "message": f"已刷新 {cached_count} 个文件的缓存"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ================= 统计API =================
    
    def get_statistics(self, host_id: str, log_type: str,
                       time_range_hours: int = None) -> Dict[str, Any]:
        """
        获取统计数据
        
        Args:
            host_id: 主机ID
            log_type: 日志类型
            time_range_hours: 时间范围(小时)
            
        Returns:
            统计数据
        """
        if not self._scanned:
            self.scan()
        
        try:
            return self.cache_manager.get_statistics(log_type, host_id, time_range_hours)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_login_statistics(self, host_id: str = None,
                             time_range_hours: int = None) -> Dict[str, Any]:
        """
        获取登录统计 (安全相关) - 使用统一的统计服务
        
        Args:
            host_id: 主机ID
            time_range_hours: 时间范围(小时), None表示全部时间
            
        Returns:
            登录统计数据
        """
        if not self._scanned:
            self.scan()
        
        try:
            from .core.statistics_service import StatisticsService
            
            # 转换时间范围
            if time_range_hours is None:
                time_range = "all"
            elif time_range_hours <= 1:
                time_range = "1h"
            elif time_range_hours <= 6:
                time_range = "6h"
            elif time_range_hours <= 24:
                time_range = "24h"
            elif time_range_hours <= 168:
                time_range = "7d"
            elif time_range_hours <= 720:
                time_range = "30d"
            else:
                time_range = "all"
            
            stats_service = StatisticsService(self.cache_manager.db_path)
            return stats_service.get_host_statistics(host_id, time_range)
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def get_dashboard_stats(self, host_id: str = None,
                            time_range: str = "all") -> Dict[str, Any]:
        """
        获取仪表盘统计数据 - 使用统一的统计服务
        
        Args:
            host_id: 主机ID (可选，不指定则汇总所有主机)
            time_range: 时间范围 (1h, 6h, 24h, 7d, 30d, all)
            
        Returns:
            仪表盘数据
        """
        if not self._scanned:
            self.scan()
        
        try:
            from .core.statistics_service import StatisticsService
            
            print(f"[API] get_dashboard_stats: host_id={host_id}, time_range={time_range}")
            
            stats_service = StatisticsService(self.cache_manager.db_path)
            result = stats_service.get_host_statistics(host_id, time_range)
            
            if result.get("success"):
                stats = result.get("statistics", {})
                print(f"[API] 统计结果: login_success={stats.get('login_success')}, login_failed={stats.get('login_failed')}")
                
                return {
                    "success": True,
                    "stats": stats,
                    "time_range": time_range,
                    "host_id": host_id
                }
            else:
                return result
                
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    # ================= 缓存管理API =================
    
    def get_cache_info(self) -> Dict[str, Any]:
        """获取缓存信息"""
        try:
            return self.cache_manager.get_cache_info()
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def clear_cache(self, file_path: str = None, log_type: str = None,
                    host_id: str = None) -> Dict[str, Any]:
        """清除缓存"""
        try:
            return self.cache_manager.clear_cache(file_path, log_type, host_id)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ================= 汇聚信息和导入历史API =================
    
    def get_aggregation_summary(self, host_id: str) -> List[Dict[str, Any]]:
        """获取主机的汇聚摘要"""
        try:
            from .core.statistics_service import StatisticsService
            stats_service = StatisticsService(self.cache_manager.db_path)
            return stats_service.get_aggregation_summary(host_id, self.cache_manager)
        except Exception as e:
            print(f"[API] 获取汇聚摘要失败: {e}")
            return []
    
    def get_import_history(self, file_path: str = None, 
                          time_range_hours: int = None,
                          limit: int = 100) -> List[Dict[str, Any]]:
        """获取导入历史记录"""
        try:
            return self.cache_manager.get_import_history(file_path, time_range_hours, limit)
        except Exception as e:
            print(f"[API] 获取导入历史失败: {e}")
            return []
    
    def verify_import_consistency(self, file_path: str) -> Dict[str, Any]:
        """验证导入数据一致性"""
        try:
            return self.cache_manager.verify_import_consistency(file_path)
        except Exception as e:
            print(f"[API] 验证一致性失败: {e}")
            return {
                "consistent": False,
                "expected_count": 0,
                "actual_count": 0,
                "difference": 0,
                "issues": [f"验证失败: {str(e)}"]
            }
    
    def load_single_file(self, file_path: str) -> Dict[str, Any]:
        """
        加载单个日志文件（自动识别类型）
        
        Args:
            file_path: 文件路径
            
        Returns:
            {
                "success": True,
                "log_type": "secure",
                "event_count": 100,
                "host_id": "..."
            }
        """
        try:
            if not os.path.exists(file_path):
                return {"success": False, "error": f"文件不存在: {file_path}"}
            
            # 识别日志类型
            file_name = os.path.basename(file_path).lower()
            log_type_str = None
            
            # 根据文件名识别类型
            if 'secure' in file_name:
                log_type_str = 'secure'
            elif 'auth' in file_name:
                log_type_str = 'auth'
            elif 'audit' in file_name:
                log_type_str = 'audit'
            elif 'btmp' in file_name:
                log_type_str = 'btmp'
            elif 'wtmp' in file_name:
                log_type_str = 'wtmp'
            elif 'lastlog' in file_name:
                log_type_str = 'lastlog'
            elif 'messages' in file_name:
                log_type_str = 'messages'
            elif 'syslog' in file_name:
                log_type_str = 'syslog'
            elif 'cron' in file_name:
                log_type_str = 'cron'
            elif 'anaconda' in file_name:
                log_type_str = 'syslog'  # anaconda日志使用syslog解析器
            else:
                # 尝试读取文件内容识别
                log_type_str = self._detect_log_type(file_path)
            
            if not log_type_str:
                # 默认使用syslog解析器
                log_type_str = 'syslog'
            
            # 检查日志类型是否在BETA版本中支持
            from .core.log_types import is_log_type_supported, get_log_type_info, SUPPORTED_LOG_TYPES
            if not is_log_type_supported(log_type_str):
                type_info = get_log_type_info(log_type_str)
                return {
                    "success": False,
                    "error": f"BETA版本暂不支持此日志类型: {type_info.get('name', log_type_str)}",
                    "log_type": log_type_str,
                    "is_supported": False,
                    "supported_types": SUPPORTED_LOG_TYPES
                }
            
            # 转换为LogType枚举
            try:
                log_type_enum = LogType(log_type_str)
            except ValueError:
                log_type_enum = LogType.SYSLOG  # 默认
            
            # 创建临时主机ID
            host_id = "手动导入"
            
            # 创建文件信息
            file_info = LogFileInfo(
                file_path=file_path,
                file_name=os.path.basename(file_path),
                log_type=log_type_enum,
                host_id=host_id,
                size=os.path.getsize(file_path),
                mtime=os.path.getmtime(file_path)
            )
            
            # 将文件添加到host_manager中，以便后续load_events_cached能找到
            if host_id not in self.host_manager.hosts:
                self.host_manager.hosts[host_id] = HostInfo(
                    host_id=host_id,
                    host_type="manual",
                    display_name="手动导入",
                    directory=""
                )
            
            # 添加到files_by_host
            # 检查是否已存在，避免重复添加
            existing_paths = [f.file_path for f in self.host_manager.files_by_host[host_id]]
            if file_path not in existing_paths:
                self.host_manager.files_by_host[host_id].append(file_info)
                
                # 同时更新 categories_by_host，确保 get_host_tree 能返回正确的数据
                config = get_log_type_config(log_type_enum)
                if config:
                    category = config.category
                    if category not in self.host_manager.categories_by_host[host_id]:
                        self.host_manager.categories_by_host[host_id][category] = CategoryGroup(category=category)
                    
                    cat_group = self.host_manager.categories_by_host[host_id][category]
                    if log_type_enum not in cat_group.log_types:
                        cat_group.log_types[log_type_enum] = []
                    
                    # 检查是否已存在
                    existing_in_cat = [f.file_path for f in cat_group.log_types[log_type_enum]]
                    if file_path not in existing_in_cat:
                        cat_group.log_types[log_type_enum].append(file_info)
                
                # 更新主机统计信息
                host = self.host_manager.hosts[host_id]
                host.total_files = len(self.host_manager.files_by_host[host_id])
                host.total_size = sum(f.size for f in self.host_manager.files_by_host[host_id])
            
            # 缓存文件
            self._cache_file(file_info, host_id)
            
            # Get events数
            cache_info = self.cache_manager.get_cache_info()
            event_count = 0
            if cache_info.get("success"):
                for f in cache_info.get("files", []):
                    if f["file_path"] == file_path:
                        event_count = f.get("event_count", 0)
                        break
            
            return {
                "success": True,
                "log_type": log_type_str,
                "event_count": event_count,
                "host_id": host_id,
                "file_path": file_path
            }
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def _detect_log_type(self, file_path: str) -> Optional[str]:
        """通过文件内容检测日志类型"""
        try:
            # 尝试读取前几行
            with open(file_path, 'rb') as f:
                header = f.read(1024)
            
            # 检查是否是二进制文件 (utmp/wtmp/btmp)
            if b'\x00' in header[:100]:
                # 可能是二进制日志
                return 'wtmp'  # 默认当作wtmp处理
            
            # 文本日志
            try:
                text = header.decode('utf-8', errors='ignore')
                
                if 'sshd' in text or 'pam_unix' in text:
                    return 'secure'
                elif 'type=' in text and 'msg=audit' in text:
                    return 'audit'
                elif 'CRON' in text or 'cron' in text:
                    return 'cron'
                else:
                    return 'syslog'  # 默认当作syslog处理
            except:
                pass
            
            return None
        except:
            return None
    
    def get_categories(self) -> List[Dict[str, Any]]:
        """
        获取日志分类列表(用于侧边栏下拉框)
        
        Returns:
            [
                {
                    "id": "安全认证",
                    "name": "安全认证",
                    "types": ["audit", "secure", "auth", "btmp", "wtmp", "lastlog"],
                    "groups": 10,
                    "files": 50,
                    "size": 1024000
                },
                ...
            ]
        """
        if not self._scanned:
            self.scan()
        
        result = []
        for category, groups in self.manager.get_groups_by_category().items():
            types = list(set(g.log_type.value for g in groups))
            result.append({
                "id": category.value,
                "name": category.value,
                "types": types,
                "groups": len(groups),
                "files": sum(g.file_count for g in groups),
                "size": sum(g.total_size for g in groups),
            })
        
        return result
    
    def get_log_types(self) -> List[Dict[str, Any]]:
        """
        获取所有日志类型定义
        
        Returns:
            [
                {
                    "id": "audit",
                    "name": "审计日志",
                    "name_en": "Audit Log",
                    "description": "...",
                    "category": "安全认证",
                    "format": "audit"
                },
                ...
            ]
        """
        result = []
        for log_type, config in LOG_TYPE_CONFIGS.items():
            result.append({
                "id": log_type.value,
                "name": config.name,
                "name_en": config.name_en,
                "description": config.description,
                "category": config.category.value,
                "format": config.format,
                "priority": config.priority,
            })
        return result
    
    def get_groups(self, category: str = None, log_type: str = None) -> List[Dict[str, Any]]:
        """
        获取文件组列表
        
        Args:
            category: 按分类筛选
            log_type: 按类型筛选
            
        Returns:
            文件组列表
        """
        if not self._scanned:
            self.scan()
        
        groups = list(self.manager.file_groups.values())
        
        # 筛选
        if category:
            groups = [g for g in groups 
                     if get_log_type_config(g.log_type).category.value == category]
        
        if log_type:
            try:
                lt = LogType(log_type)
                groups = [g for g in groups if g.log_type == lt]
            except:
                pass
        
        # 转换为字典
        result = []
        for group in groups:
            config = get_log_type_config(group.log_type)
            result.append({
                "group_key": group.group_key,
                "log_type": group.log_type.value,
                "type_name": group.type_name,
                "category": config.category.value if config else "",
                "file_count": group.file_count,
                "total_size": group.total_size,
                "files": [
                    {"name": f.filename, "path": f.path, "size": f.size}
                    for f in group.files
                ]
            })
        
        return result
    
    def get_events(self, group_key: str, page: int = 1, page_size: int = 100,
                   filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        获取日志事件(分页)
        
        Args:
            group_key: 文件组键
            page: 页码
            page_size: 每页大小
            filters: 筛选条件
            
        Returns:
            {
                "events": [...],
                "pagination": {...},
                "fields": [...]
            }
        """
        if not self._scanned:
            self.scan()
        
        group = self.manager.file_groups.get(group_key)
        if not group:
            return {"events": [], "pagination": {}, "fields": [], "error": "文件组不存在"}
        
        # Get parser字段定义
        parser = self.manager.get_parser(group.log_type)
        fields = parser.get_fields() if parser else []
        
        # 分页解析
        result = self.manager.parse_group_paginated(group, page, page_size)
        result["fields"] = fields
        result["group_key"] = group_key
        result["log_type"] = group.log_type.value
        result["type_name"] = group.type_name
        
        return result
    
    def get_group_statistics(self, group_key: str) -> Dict[str, Any]:
        """
        获取文件组统计信息
        
        Args:
            group_key: 文件组键
            
        Returns:
            统计信息
        """
        if not self._scanned:
            self.scan()
        
        group = self.manager.file_groups.get(group_key)
        if not group:
            return {"error": "文件组不存在"}
        
        # 统计
        stats = {
            "total_events": 0,
            "by_event_type": {},
            "by_user": {},
            "by_source_ip": {},
            "by_result": {},
            "by_level": {},
            "time_range": {"start": None, "end": None},
        }
        
        for event in self.manager.parse_group(group):
            stats["total_events"] += 1
            
            # 按事件类型
            et = event.event_type or "UNKNOWN"
            stats["by_event_type"][et] = stats["by_event_type"].get(et, 0) + 1
            
            # 按用户
            if event.user:
                stats["by_user"][event.user] = stats["by_user"].get(event.user, 0) + 1
            
            # 按来源IP
            if event.source_ip:
                stats["by_source_ip"][event.source_ip] = stats["by_source_ip"].get(event.source_ip, 0) + 1
            
            # 按结果
            if event.result:
                stats["by_result"][event.result] = stats["by_result"].get(event.result, 0) + 1
            
            # 按级别
            stats["by_level"][event.level] = stats["by_level"].get(event.level, 0) + 1
            
            # 时间范围
            if event.timestamp:
                ts_str = event.timestamp_str
                if not stats["time_range"]["start"] or ts_str < stats["time_range"]["start"]:
                    stats["time_range"]["start"] = ts_str
                if not stats["time_range"]["end"] or ts_str > stats["time_range"]["end"]:
                    stats["time_range"]["end"] = ts_str
        
        # 排序Top N
        stats["by_event_type"] = dict(sorted(stats["by_event_type"].items(), key=lambda x: -x[1])[:20])
        stats["by_user"] = dict(sorted(stats["by_user"].items(), key=lambda x: -x[1])[:20])
        stats["by_source_ip"] = dict(sorted(stats["by_source_ip"].items(), key=lambda x: -x[1])[:20])
        
        return stats
    
    def search_events(self, group_key: str, query: str = None, 
                      filters: Dict[str, Any] = None,
                      page: int = 1, page_size: int = 100) -> Dict[str, Any]:
        """
        搜索日志事件
        
        Args:
            group_key: 文件组键
            query: 搜索关键词
            filters: 筛选条件 {"user": "root", "source_ip": "192.168.1.1", ...}
            page: 页码
            page_size: 每页大小
            
        Returns:
            搜索结果
        """
        if not self._scanned:
            self.scan()
        
        group = self.manager.file_groups.get(group_key)
        if not group:
            return {"events": [], "pagination": {}, "error": "文件组不存在"}
        
        events = []
        total_count = 0
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        
        for event in self.manager.parse_group(group):
            # 应用筛选
            if not self._match_filters(event, query, filters):
                continue
            
            total_count += 1
            if start_idx <= (total_count - 1) < end_idx:
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
            },
            "query": query,
            "filters": filters
        }
    
    def _match_filters(self, event, query: str = None, filters: Dict = None) -> bool:
        """检查事件是否匹配筛选条件"""
        # 关键词搜索
        if query:
            query_lower = query.lower()
            searchable = f"{event.user} {event.source_ip} {event.message} {event.event_name}".lower()
            if query_lower not in searchable:
                return False
        
        # 字段筛选
        if filters:
            for field, value in filters.items():
                if not value:
                    continue
                event_value = getattr(event, field, None)
                if event_value is None:
                    return False
                if isinstance(value, str) and isinstance(event_value, str):
                    if value.lower() not in event_value.lower():
                        return False
                elif event_value != value:
                    return False
        
        return True


# 全局API实例
_api_instance = None


def get_api(base_dir: str = "logs") -> LinuxLogAPI:
    """获取API实例(单例)"""
    global _api_instance
    if _api_instance is None:
        _api_instance = LinuxLogAPI(base_dir)
    return _api_instance
