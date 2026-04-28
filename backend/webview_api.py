#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Linux日志分析 - PyWebview API
提供给前端调用的接口
"""

import os
import sys

from .api import LinuxLogAPI


class LinuxLogWebAPI:
    """Linux日志分析 PyWebview API"""
    
    def __init__(self):
        self.api = LinuxLogAPI(base_dir="logs")
        self._load_progress = {}  # 加载进度跟踪
        print(f"[LinuxLogWebAPI] 初始化完成")
    
    # ================= 窗口控制 =================
    
    def fullscreen(self):
        """切换全屏"""
        import webview
        webview.windows[0].toggle_fullscreen()
    
    def minimize(self):
        """最小化"""
        import webview
        webview.windows[0].minimize()
    
    def get_version(self):
        """获取版本信息"""
        return {
            "version": "1.0.0",
            "name": "Linux Log Analyzer"
        }
    
    def open_file_dialog(self):
        """打开文件选择对话框 - 选择日志文件"""
        import webview
        try:
            # 使用新的FileDialog API
            dialog_type = getattr(webview, 'OPEN_DIALOG', None)
            if dialog_type is None:
                # 新版本pywebview使用FileDialog枚举
                from webview import FileDialog
                dialog_type = FileDialog.OPEN
            
            result = webview.windows[0].create_file_dialog(
                dialog_type,
                allow_multiple=True,
                file_types=(
                    '所有文件 (*.*)',
                    '日志文件 (*.log)',
                )
            )
            if result:
                files = list(result)
                # 自动识别并加载选择的文件
                loaded_files = []
                for file_path in files:
                    try:
                        # 识别日志类型并加载
                        load_result = self.api.load_single_file(file_path)
                        if load_result.get("success"):
                            loaded_files.append({
                                "file": file_path,
                                "log_type": load_result.get("log_type"),
                                "event_count": load_result.get("event_count", 0),
                                "host_id": load_result.get("host_id")
                            })
                    except Exception as e:
                        print(f"加载文件失败 {file_path}: {e}")
                
                return {
                    "success": True, 
                    "files": files,
                    "loaded_files": loaded_files,
                    "message": f"成功加载 {len(loaded_files)} 个文件"
                }
            return {"success": False, "error": "用户取消"}
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def open_folder_dialog(self):
        """打开文件夹选择对话框"""
        import webview
        try:
            # 使用新的FileDialog API
            dialog_type = getattr(webview, 'FOLDER_DIALOG', None)
            if dialog_type is None:
                # 新版本pywebview使用FileDialog枚举
                from webview import FileDialog
                dialog_type = FileDialog.FOLDER
            
            result = webview.windows[0].create_file_dialog(dialog_type)
            if result:
                folder = result[0] if isinstance(result, (list, tuple)) else result
                # 扫描选择的目录
                scan_result = self.api.scan(folder)
                return {"success": True, "folder": folder, **scan_result}
            return {"success": False, "error": "用户取消"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ================= 扫描和主机管理 =================
    
    def linux_scan(self, directory=None):
        """扫描日志目录"""
        try:
            result = self.api.scan(directory)
            return {"success": True, **result}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def linux_get_hosts(self):
        """获取主机列表"""
        return self.api.get_hosts()
    
    def linux_get_host_tree(self):
        """获取主机树形结构"""
        result = self.api.get_host_tree()
        
        # 添加事件行数信息
        if result.get("success") and result.get("tree"):
            cache_info = self.api.cache_manager.get_cache_info()
            file_events = {}
            if cache_info.get("success") and cache_info.get("files"):
                for f in cache_info["files"]:
                    file_events[f["file_path"]] = f.get("event_count", 0)
            
            # 更新树中的事件数
            for host in result["tree"]:
                for category in host.get("categories", []):
                    for log_type in category.get("log_types", []):
                        total_events = 0
                        for file_info in log_type.get("files", []):
                            event_count = file_events.get(file_info["file_path"], 0)
                            file_info["event_count"] = event_count
                            total_events += event_count
                        log_type["total_events"] = total_events
        
        return result
    
    def linux_get_categories(self):
        """获取日志分类"""
        try:
            categories = self.api.get_categories()
            return {"success": True, "categories": categories}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def linux_get_log_types(self):
        """获取日志类型定义"""
        try:
            types = self.api.get_log_types()
            return {"success": True, "types": types}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def linux_check_log_type_support(self, log_type: str):
        """
        检查日志类型是否在BETA版本中支持
        
        Args:
            log_type: 日志类型字符串
            
        Returns:
            {
                "success": True,
                "log_type": "messages",
                "name": "系统消息",
                "is_supported": False,
                "supported_types": ["audit", "secure", "auth", "btmp", "wtmp", "lastlog"]
            }
        """
        try:
            from .core.log_types import get_log_type_info
            info = get_log_type_info(log_type)
            return {"success": True, **info}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ================= 事件加载 =================
    
    def linux_load_events(self, host_id, log_type, page=1, page_size=100,
                          sort_field="timestamp_unix", sort_direction="desc"):
        """加载日志事件（分页）"""
        try:
            result = self.api.load_events_cached(
                host_id=host_id,
                log_type=log_type,
                page=page,
                page_size=page_size,
                sort_field=sort_field,
                sort_direction=sort_direction
            )
            return result
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def linux_search_events(self, host_id, log_type, search_term=None,
                            filters=None, page=1, page_size=100):
        """搜索日志事件"""
        try:
            # 解析过滤条件格式: {"field": "operator:value"}
            parsed_filters = {}
            date_start = None
            date_end = None
            
            if filters:
                for field, condition in filters.items():
                    # 处理日期范围
                    if field == 'date_start':
                        date_start = condition
                        continue
                    if field == 'date_end':
                        date_end = condition
                        continue
                    
                    if isinstance(condition, str) and ':' in condition:
                        # 格式: "contains:value" 或 "equals:value"
                        parts = condition.split(':', 1)
                        operator = parts[0]
                        value = parts[1] if len(parts) > 1 else ''
                        if value.strip():
                            parsed_filters[field] = {
                                'operator': operator,
                                'value': value
                            }
                    elif condition:
                        # 简单值，默认包含匹配
                        parsed_filters[field] = {
                            'operator': 'contains',
                            'value': str(condition)
                        }
            
            # 先加载数据（分页加载，避免性能问题）
            result = self.api.load_events_cached(
                host_id=host_id,
                log_type=log_type,
                page=1,
                page_size=5000,  # 限制最大加载量
                sort_field="timestamp_unix",
                sort_direction="desc"
            )
            
            if not result.get("success"):
                return result
            
            events = result.get("events", [])
            
            # 应用过滤条件
            filtered_events = []
            for event in events:
                match = True
                
                # 日期范围过滤
                if date_start or date_end:
                    event_time = event.get('timestamp_str', '')
                    if event_time:
                        # 转换日期格式进行比较
                        try:
                            # 处理datetime-local格式 (2024-01-01T12:00)
                            if date_start:
                                start_str = date_start.replace('T', ' ')
                                if event_time < start_str:
                                    match = False
                            if date_end and match:
                                end_str = date_end.replace('T', ' ')
                                if event_time > end_str:
                                    match = False
                        except:
                            pass
                
                # 全文搜索
                if match and search_term and search_term.strip():
                    search_lower = search_term.lower()
                    searchable = " ".join(str(v) for v in event.values() if v).lower()
                    if search_lower not in searchable:
                        match = False
                
                # 字段过滤
                if match and parsed_filters:
                    for field, cond in parsed_filters.items():
                        field_value = str(event.get(field, '') or '').lower()
                        filter_value = cond['value'].lower()
                        operator = cond['operator']
                        
                        if operator == 'contains':
                            if filter_value not in field_value:
                                match = False
                        elif operator == 'equals':
                            if field_value != filter_value:
                                match = False
                        elif operator == 'not_contains':
                            if filter_value in field_value:
                                match = False
                        elif operator == 'not_equals':
                            if field_value == filter_value:
                                match = False
                        elif operator == 'starts_with':
                            if not field_value.startswith(filter_value):
                                match = False
                        elif operator == 'ends_with':
                            if not field_value.endswith(filter_value):
                                match = False
                        
                        if not match:
                            break
                
                if match:
                    filtered_events.append(event)
            
            # 分页
            total_count = len(filtered_events)
            total_pages = max(1, (total_count + page_size - 1) // page_size)
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            paged_events = filtered_events[start_idx:end_idx]
            
            return {
                "success": True,
                "events": paged_events,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_count": total_count,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1
                }
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    # ================= 统计和仪表盘 =================
    
    def linux_get_dashboard_stats(self, host_id=None, time_range="all"):
        """获取仪表盘统计 - 统一使用统计服务"""
        return self._get_unified_statistics(host_id, time_range)
    
    def linux_get_statistics(self, host_id, log_type=None, time_range="all"):
        """获取详细统计 - 统一使用统计服务"""
        return self._get_unified_statistics(host_id, time_range, log_type)
    
    def _get_unified_statistics(self, host_id=None, time_range="all", log_type=None):
        """
        统一的统计接口
        无论是概览还是统计页面，都使用相同的数据源
        """
        try:
            from .core.statistics_service import StatisticsService
            
            print(f"[WebAPI] 统一统计: host_id={host_id}, time_range={time_range}, log_type={log_type}")
            
            # 创建统计服务
            stats_service = StatisticsService(self.api.cache_manager.db_path)
            
            # Get hosts统计
            result = stats_service.get_host_statistics(host_id, time_range)
            
            if result.get("success"):
                stats = result.get("statistics", {})
                
                # 如果指定了日志类型，额外获取该类型的事件分布
                if log_type:
                    type_stats = self.api.get_statistics(host_id, log_type, 
                        {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720, "all": None}.get(time_range))
                    if type_stats.get("success"):
                        by_type = type_stats.get("statistics", {}).get("by_event_type", {})
                        if by_type:
                            stats["event_type_distribution"] = [
                                {"type": k, "count": v} 
                                for k, v in sorted(by_type.items(), key=lambda x: -x[1])
                            ]
                
                print(f"[WebAPI] 统计结果: login_success={stats.get('login_success')}, login_failed={stats.get('login_failed')}")
                
                return {
                    "success": True,
                    "stats": stats,
                    "statistics": stats,
                    "time_range": time_range
                }
            else:
                return result
                
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def linux_get_filtered_events(self, params: dict):
        """
        获取按IP或用户过滤的事件列表
        用于详情面板展示
        """
        try:
            from .core.statistics_service import StatisticsService
            
            host_id = params.get('host_id')
            filter_type = params.get('filter_type')  # 'ip' or 'user'
            filter_value = params.get('filter_value')
            time_range = params.get('time_range', 'all')  # 添加时间范围参数
            search_term = params.get('search_term')
            date_start = params.get('date_start')
            date_end = params.get('date_end')
            result_filter = params.get('result_filter')
            event_type_filter = params.get('event_type_filter')
            page = params.get('page', 1)
            page_size = params.get('page_size', 50)
            sort_field = params.get('sort_field', 'timestamp_unix')
            sort_direction = params.get('sort_direction', 'desc')
            
            print(f"[WebAPI] linux_get_filtered_events: host_id={host_id}, filter_type={filter_type}, filter_value={filter_value}, time_range={time_range}")
            
            stats_service = StatisticsService(self.api.cache_manager.db_path)
            result = stats_service.get_filtered_events(
                host_id=host_id,
                filter_type=filter_type,
                filter_value=filter_value,
                time_range=time_range,  # 传递时间范围参数
                search_term=search_term,
                date_start=date_start,
                date_end=date_end,
                result_filter=result_filter,
                event_type_filter=event_type_filter,
                page=page,
                page_size=page_size,
                sort_field=sort_field,
                sort_direction=sort_direction,
                cache_manager=self.api.cache_manager  # 传递cache_manager以获取完整的source_info
            )
            
            return result
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def linux_get_login_statistics(self, host_id=None, time_range_hours=24):
        """获取登录统计"""
        return self.api.get_login_statistics(host_id, time_range_hours)
    
    def linux_get_file_statistics(self, file_path: str, time_range: str = "all"):
        """获取单个文件的统计"""
        try:
            time_hours = {
                "1h": 1, "6h": 6, "24h": 24,
                "7d": 168, "30d": 720, "all": None
            }.get(time_range, None)
            
            result = self.api.cache_manager.get_file_statistics(file_path, time_hours)
            return result
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    # ================= 汇聚信息和导入历史 =================
    
    def linux_get_aggregation_summary(self, host_id: str):
        """
        获取主机的汇聚摘要
        
        Args:
            host_id: 主机ID
            
        Returns:
            {
                "success": True,
                "summaries": [
                    {
                        "log_type": "wtmp",
                        "table_name": "events_wtmp_xxx",
                        "file_count": 5,
                        "total_events": 6789,
                        "aggregation_display": "5个文件 → 1个表",
                        "files": [...]
                    },
                    ...
                ]
            }
        """
        try:
            summaries = self.api.get_aggregation_summary(host_id)
            return {
                "success": True,
                "summaries": summaries
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def linux_get_import_history(self, file_path: str = None, time_range_hours: int = None, limit: int = 100):
        """
        获取导入历史记录
        
        Args:
            file_path: 文件路径（可选）
            time_range_hours: 时间范围（小时）
            limit: 返回记录数限制
            
        Returns:
            {
                "success": True,
                "history": [...]
            }
        """
        try:
            history = self.api.get_import_history(file_path, time_range_hours, limit)
            return {
                "success": True,
                "history": history
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def linux_verify_consistency(self, file_path: str):
        """
        验证导入数据一致性
        
        Args:
            file_path: 文件路径
            
        Returns:
            {
                "success": True,
                "consistent": True/False,
                "expected_count": 1234,
                "actual_count": 1234,
                "difference": 0,
                "issues": []
            }
        """
        try:
            result = self.api.verify_import_consistency(file_path)
            return {
                "success": True,
                **result
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    # ================= 缓存管理 =================
    
    def linux_get_cache_info(self):
        """获取缓存信息"""
        return self.api.get_cache_info()
    
    def linux_clear_cache(self, file_path=None, log_type=None, host_id=None):
        """清除缓存"""
        return self.api.clear_cache(file_path, log_type, host_id)
    
    def linux_refresh_cache(self, host_id=None, log_type=None):
        """刷新缓存"""
        return self.api.refresh_cache(host_id, log_type)
    
    # ================= 进度跟踪 =================
    
    def linux_get_load_progress(self, host_id=None, log_type=None):
        """获取加载进度"""
        key = f"{host_id or 'all'}_{log_type or 'all'}"
        progress = self._load_progress.get(key, {
            "status": "idle",
            "current": 0,
            "total": 0,
            "message": "",
            "file_name": "",
            "percent": 0
        })
        return {"success": True, **progress}
    
    def linux_load_with_progress(self, host_id, log_type):
        """带进度的加载（用于首次加载大文件）"""
        import threading
        import time
        
        key = f"{host_id}_{log_type}"
        
        def load_task():
            try:
                self._load_progress[key] = {
                    "status": "loading",
                    "current": 0,
                    "total": 0,
                    "message": "正在扫描文件...",
                    "file_name": "",
                    "percent": 0
                }
                
                # Get files列表
                files = self.api.host_manager.get_files_by_host_and_type(host_id, log_type)
                total_files = len(files)
                
                if total_files == 0:
                    self._load_progress[key] = {
                        "status": "done",
                        "current": 0,
                        "total": 0,
                        "message": "没有找到日志文件",
                        "file_name": "",
                        "percent": 100
                    }
                    return
                
                # 估算总行数（基于文件大小）
                total_size = sum(f.size for f in files)
                # 审计日志每行约150字节，其他日志约100字节
                bytes_per_line = 150 if log_type == 'audit' else 100
                estimated_total = max(1, int(total_size / bytes_per_line))
                
                self._load_progress[key] = {
                    "status": "loading",
                    "current": 0,
                    "total": estimated_total,
                    "message": f"准备加载 {total_files} 个文件...",
                    "file_name": "",
                    "percent": 0
                }
                
                # 逐个缓存文件，使用带进度回调的方式
                total_cached = 0
                for idx, file_info in enumerate(files):
                    file_name = file_info.file_name
                    file_size = file_info.size
                    estimated_lines = max(1, int(file_size / bytes_per_line))
                    
                    # 更新当前文件信息
                    self._load_progress[key] = {
                        "status": "loading",
                        "current": total_cached,
                        "total": estimated_total,
                        "message": f"正在处理 ({idx+1}/{total_files})",
                        "file_name": file_name,
                        "percent": int((total_cached / estimated_total) * 100) if estimated_total > 0 else 0
                    }
                    
                    # 使用带进度回调的缓存方法
                    def progress_callback(current_lines, total_lines_in_file):
                        nonlocal total_cached
                        current_total = total_cached + current_lines
                        percent = int((current_total / estimated_total) * 100) if estimated_total > 0 else 0
                        self._load_progress[key] = {
                            "status": "loading",
                            "current": current_total,
                            "total": estimated_total,
                            "message": f"正在处理 ({idx+1}/{total_files})",
                            "file_name": file_name,
                            "percent": min(99, percent)  # 保留1%给完成状态
                        }
                    
                    # 缓存文件
                    cached_count = self._cache_file_with_progress(file_info, host_id, progress_callback)
                    total_cached += cached_count
                
                self._load_progress[key] = {
                    "status": "done",
                    "current": total_cached,
                    "total": total_cached,
                    "message": f"完成！共 {total_cached:,} 条事件",
                    "file_name": "",
                    "percent": 100
                }
                
            except Exception as e:
                import traceback
                traceback.print_exc()
                self._load_progress[key] = {
                    "status": "error",
                    "current": 0,
                    "total": 0,
                    "message": f"加载失败: {str(e)}",
                    "file_name": "",
                    "percent": 0
                }
        
        # 启动后台线程
        thread = threading.Thread(target=load_task, daemon=True)
        thread.start()
        
        return {"success": True, "message": "开始加载"}
    
    def _cache_file_with_progress(self, file_info, host_id, progress_callback=None):
        """带进度回调的文件缓存"""
        try:
            from .core.log_types import is_log_type_supported
            log_type_str = file_info.log_type.value if hasattr(file_info.log_type, 'value') else str(file_info.log_type)
            
            if not is_log_type_supported(log_type_str):
                return 0
            
            parser = self.api.manager.get_parser(file_info.log_type)
            if not parser:
                return 0
            
            # 设置源文件路径
            if hasattr(parser, 'set_source_file'):
                parser.set_source_file(file_info.file_path)
            
            # 使用带进度的缓存方法
            result = self.api.cache_manager.cache_events_with_progress(
                file_path=file_info.file_path,
                log_type=log_type_str,
                host_id=host_id,
                events=parser.parse_file(file_info.file_path),
                progress_callback=progress_callback,
                show_progress=False
            )
            
            return result.get('event_count', 0) if result.get('success') else 0
            
        except Exception as e:
            print(f"[WebAPI] 缓存文件失败 {file_info.file_path}: {e}")
            return 0

    # ================= 年份管理 =================
    
    def linux_get_year_suggestion(self, file_path: str):
        """获取文件的年份建议"""
        try:
            from .core.year_resolver import year_resolver
            result = year_resolver.get_year_suggestion(file_path)
            return {"success": True, **result}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def linux_set_file_year(self, file_path: str, year: int):
        """设置文件的年份并重新解析"""
        try:
            from .core.year_resolver import year_resolver
            
            print(f"[WebAPI] 设置文件年份: {file_path} -> {year}")
            
            # 设置手动年份
            year_resolver.set_manual_year(file_path, year)
            
            # 清除该文件的事件缓存，下次加载时会使用新年份
            self.api.clear_cache(file_path=file_path)
            
            # 重新获取年份信息验证
            result = year_resolver.get_year_suggestion(file_path)
            
            print(f"[WebAPI] 设置后年份信息: {result}")
            
            return {
                "success": True,
                "year": result["suggested_year"],
                "source": result["source"],
                "message": f"已设置年份为 {year}，缓存已清除"
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def linux_get_files_year_info(self, host_id: str, log_type: str):
        """获取指定主机和日志类型的所有文件年份信息"""
        try:
            from .core.year_resolver import year_resolver
            
            files = self.api.host_manager.get_files_by_host_and_type(host_id, log_type)
            
            year_infos = []
            for file_info in files:
                info = year_resolver.get_year_suggestion(file_info.file_path)
                year_infos.append({
                    "file_path": file_info.file_path,
                    "file_name": file_info.file_name,
                    **info
                })
            
            return {"success": True, "files": year_infos}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ================= 审计日志统计 =================
    
    def linux_get_audit_statistics(self, host_id: str, time_range: str = 'all'):
        """
        获取审计日志统计
        
        Args:
            host_id: 主机ID
            time_range: 时间范围 ('1h', '6h', '24h', '7d', '30d', 'all')
            
        Returns:
            {
                "success": True,
                "statistics": {...}
            }
        """
        try:
            from .core.audit_statistics import AuditStatisticsService
            
            print(f"[WebAPI] 审计统计: host_id={host_id}, time_range={time_range}")
            
            service = AuditStatisticsService(self.api.cache_manager.db_path)
            result = service.get_audit_statistics(host_id, time_range)
            
            return result
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def linux_get_audit_events(self, host_id: str, event_category: str = None,
                               event_type: str = None, user: str = None,
                               source_ip: str = None, result: str = None,
                               time_range: str = 'all', page: int = 1,
                               page_size: int = 50):
        """
        获取审计事件列表
        
        Args:
            host_id: 主机ID
            event_category: 事件分类筛选
            event_type: 事件类型筛选
            user: 用户筛选
            source_ip: 来源IP筛选
            result: 结果筛选 ('success', 'failed')
            time_range: 时间范围
            page: 页码
            page_size: 每页大小
            
        Returns:
            {
                "success": True,
                "events": [...],
                "pagination": {...},
                "filters": {...}
            }
        """
        try:
            from .core.audit_statistics import AuditStatisticsService
            
            print(f"[WebAPI] 审计事件: host_id={host_id}, category={event_category}, type={event_type}")
            
            service = AuditStatisticsService(self.api.cache_manager.db_path)
            result_data = service.get_filtered_audit_events(
                host_id=host_id,
                event_category=event_category,
                event_type=event_type,
                user=user,
                source_ip=source_ip,
                result=result,
                time_range=time_range,
                page=page,
                page_size=page_size
            )
            
            return result_data
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def linux_get_audit_event_detail(self, host_id: str, event_id: int):
        """
        获取审计事件详情
        
        Args:
            host_id: 主机ID
            event_id: 事件ID
            
        Returns:
            {
                "success": True,
                "event": {...}
            }
        """
        try:
            from .core.audit_statistics import AuditStatisticsService
            
            service = AuditStatisticsService(self.api.cache_manager.db_path)
            result = service.get_audit_event_detail(host_id, event_id)
            
            return result
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def linux_get_audit_filters(self, host_id: str):
        """
        获取审计日志可用的筛选选项
        
        Args:
            host_id: 主机ID
            
        Returns:
            {
                "success": True,
                "filters": {
                    "event_types": [...],
                    "event_categories": [...],
                    "users": [...],
                    "source_ips": [...]
                }
            }
        """
        try:
            from .core.audit_statistics import AuditStatisticsService
            
            service = AuditStatisticsService(self.api.cache_manager.db_path)
            result = service.get_available_filters(host_id)
            
            return result
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}

    def linux_get_filtered_audit_events(self, params: dict):
        """
        获取按IP或用户过滤的审计事件列表
        用于审计日志详情面板展示
        
        Args:
            params: {
                host_id: 主机ID
                filter_type: 过滤类型 ('ip' 或 'user')
                filter_value: 过滤值
                time_range: 时间范围
                search_term: 搜索关键词
                date_start: 开始日期
                date_end: 结束日期
                result_filter: 结果过滤
                event_type_filter: 事件类型过滤
                page: 页码
                page_size: 每页大小
                sort_field: 排序字段
                sort_direction: 排序方向
            }
        """
        try:
            from .core.statistics_service import StatisticsService
            
            host_id = params.get('host_id')
            filter_type = params.get('filter_type')  # 'ip' or 'user'
            filter_value = params.get('filter_value')
            time_range = params.get('time_range', 'all')
            search_term = params.get('search_term')
            date_start = params.get('date_start')
            date_end = params.get('date_end')
            result_filter = params.get('result_filter')
            event_type_filter = params.get('event_type_filter')
            page = params.get('page', 1)
            page_size = params.get('page_size', 50)
            sort_field = params.get('sort_field', 'timestamp_unix')
            sort_direction = params.get('sort_direction', 'desc')
            
            print(f"[WebAPI] linux_get_filtered_audit_events: host_id={host_id}, filter_type={filter_type}, filter_value={filter_value}")
            
            stats_service = StatisticsService(self.api.cache_manager.db_path)
            result = stats_service.get_filtered_audit_events(
                host_id=host_id,
                filter_type=filter_type,
                filter_value=filter_value,
                time_range=time_range,
                search_term=search_term,
                date_start=date_start,
                date_end=date_end,
                result_filter=result_filter,
                event_type_filter=event_type_filter,
                page=page,
                page_size=page_size,
                sort_field=sort_field,
                sort_direction=sort_direction
            )
            
            return result
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
