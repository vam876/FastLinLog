#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
统计服务模块
统一处理所有安全日志的统计分析
"""

import sqlite3
import hashlib
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class LogCategory(Enum):
    """日志分类"""
    SECURE = "secure"      # secure/auth 日志
    BTMP = "btmp"          # 失败登录二进制日志
    WTMP = "wtmp"          # 登录记录二进制日志
    LASTLOG = "lastlog"    # 最后登录记录
    AUDIT = "audit"        # 审计日志


@dataclass
class SecurityStats:
    """安全统计数据结构"""
    login_success: int = 0
    login_failed: int = 0
    invalid_user_attempts: int = 0
    sudo_success: int = 0
    sudo_denied: int = 0
    top_failed_ips: List[Dict[str, Any]] = field(default_factory=list)
    top_failed_users: List[Dict[str, Any]] = field(default_factory=list)
    top_success_users: List[Dict[str, Any]] = field(default_factory=list)
    top_sudo_users: List[Dict[str, Any]] = field(default_factory=list)
    hourly_timeline: List[Dict[str, Any]] = field(default_factory=list)
    event_type_distribution: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "login_success": self.login_success,
            "login_failed": self.login_failed,
            "invalid_user_attempts": self.invalid_user_attempts,
            "sudo_success": self.sudo_success,
            "sudo_denied": self.sudo_denied,
            "top_failed_ips": self.top_failed_ips,
            "top_failed_users": self.top_failed_users,
            "top_success_users": self.top_success_users,
            "top_sudo_users": self.top_sudo_users,
            "hourly_timeline": self.hourly_timeline,
            "event_type_distribution": self.event_type_distribution,
        }


class StatisticsService:
    """统计服务 - 统一处理所有统计逻辑"""
    
    # 安全相关的日志类型
    SECURITY_LOG_TYPES = ['secure', 'auth', 'btmp', 'wtmp', 'lastlog']
    
    # 审计日志类型
    AUDIT_LOG_TYPES = ['audit']
    
    # 事件类型分类
    SUCCESS_LOGIN_EVENTS = [
        'SSH_ACCEPTED_PASSWORD', 'SSH_ACCEPTED_PUBLICKEY', 
        'SSH_ACCEPTED_KEYBOARD', 'USER_PROCESS'
    ]
    FAILED_LOGIN_EVENTS = [
        'SSH_FAILED_PASSWORD', 'SSH_FAILED_PUBLICKEY',
        'LOGIN_PROCESS'  # btmp中的LOGIN_PROCESS表示失败
    ]
    INVALID_USER_EVENTS = ['SSH_INVALID_USER', 'SSH_PREAUTH_INVALID_USER']
    SUDO_SUCCESS_EVENTS = ['SUDO_COMMAND']
    SUDO_DENIED_EVENTS = ['SUDO_NOT_IN_SUDOERS']
    
    def __init__(self, db_path: str):
        self.db_path = db_path
    
    def _get_host_hash(self, host_id: str) -> str:
        """生成主机哈希"""
        return hashlib.md5(host_id.encode()).hexdigest()[:8]
    
    def _get_security_tables(self, cursor: sqlite3.Cursor, host_id: Optional[str] = None) -> List[tuple]:
        """
        获取安全相关的表列表
        返回: [(table_name, log_type), ...]
        """
        # Build query条件
        type_conditions = " OR ".join([f"name LIKE 'events_{t}%'" for t in self.SECURITY_LOG_TYPES])
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND ({type_conditions})")
        tables = cursor.fetchall()
        
        result = []
        for (table_name,) in tables:
            # 解析日志类型
            log_type = None
            for t in self.SECURITY_LOG_TYPES:
                if table_name.startswith(f'events_{t}'):
                    log_type = t
                    break
            
            # 如果指定了host_id，过滤表
            if host_id:
                host_hash = self._get_host_hash(host_id)
                if not table_name.endswith(f'_{host_hash}'):
                    continue
            
            result.append((table_name, log_type))
        
        return result
    
    def _get_audit_tables(self, cursor: sqlite3.Cursor, host_id: Optional[str] = None) -> List[tuple]:
        """
        获取审计日志相关的表列表
        返回: [(table_name, log_type), ...]
        """
        # Build query条件
        type_conditions = " OR ".join([f"name LIKE 'events_{t}%'" for t in self.AUDIT_LOG_TYPES])
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND ({type_conditions})")
        tables = cursor.fetchall()
        
        result = []
        for (table_name,) in tables:
            # 解析日志类型
            log_type = None
            for t in self.AUDIT_LOG_TYPES:
                if table_name.startswith(f'events_{t}'):
                    log_type = t
                    break
            
            # 如果指定了host_id，过滤表
            if host_id:
                host_hash = self._get_host_hash(host_id)
                if not table_name.endswith(f'_{host_hash}'):
                    continue
            
            result.append((table_name, log_type))
        
        return result
    
    def _parse_time_range(self, time_range: str) -> Optional[int]:
        """
        解析时间范围，返回最小时间戳
        注意：对于历史日志，我们不应该用当前时间来过滤
        """
        if time_range == 'all' or not time_range:
            return None  # 不过滤时间
        
        hours_map = {
            "1h": 1, "6h": 6, "24h": 24,
            "7d": 168, "30d": 720
        }
        hours = hours_map.get(time_range)
        if hours:
            return int(time.time()) - (hours * 3600)
        return None
    
    def get_host_statistics(self, host_id: str, time_range: str = "all") -> Dict[str, Any]:
        """
        获取指定主机的安全统计
        汇总该主机所有安全相关日志的数据
        """
        stats = SecurityStats()
        aggregators = {
            'failed_ips': {},
            'failed_users': {},
            'success_users': {},
            'sudo_users': {},
            'hourly_data': {},
            'event_types': {}
        }
        
        min_time = self._parse_time_range(time_range)
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            tables = self._get_security_tables(cursor, host_id)
            print(f"[StatisticsService] host_id={host_id}, time_range={time_range}, tables={[t[0] for t in tables]}")
            
            if not tables:
                conn.close()
                return {"success": True, "statistics": stats.to_dict(), "message": "无数据"}
            
            for table_name, log_type in tables:
                self._collect_table_stats(cursor, table_name, log_type, min_time, stats, aggregators)
            
            conn.close()
            
            # 转换聚合数据为列表
            self._finalize_aggregators(stats, aggregators)
            
            print(f"[StatisticsService] 结果: login_success={stats.login_success}, login_failed={stats.login_failed}")
            
            return {"success": True, "statistics": stats.to_dict()}
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def _collect_table_stats(self, cursor: sqlite3.Cursor, table_name: str, 
                             log_type: str, min_time: Optional[int],
                             stats: SecurityStats, aggregators: Dict):
        """从单个表收集统计数据"""
        
        time_condition = "timestamp_unix >= ?" if min_time else "1=1"
        time_params = [min_time] if min_time else []
        
        if log_type == 'btmp':
            self._collect_btmp_stats(cursor, table_name, time_condition, time_params, stats, aggregators)
        elif log_type == 'wtmp':
            self._collect_wtmp_stats(cursor, table_name, time_condition, time_params, stats, aggregators)
        elif log_type == 'lastlog':
            self._collect_lastlog_stats(cursor, table_name, time_condition, time_params, stats, aggregators)
        else:  # secure, auth
            self._collect_secure_stats(cursor, table_name, time_condition, time_params, stats, aggregators)
        
        # 收集事件类型分布（所有表通用）
        self._collect_event_distribution(cursor, table_name, time_condition, time_params, aggregators)
        
        # 收集时间趋势（所有表通用）
        self._collect_hourly_timeline(cursor, table_name, log_type, time_condition, time_params, aggregators)
    
    def _collect_btmp_stats(self, cursor, table_name, time_cond, time_params, stats, agg):
        """收集btmp统计 - 所有记录都是失败登录"""
        # Failed登录总数
        cursor.execute(f'SELECT COUNT(*) FROM {table_name} WHERE {time_cond}', time_params)
        stats.login_failed += cursor.fetchone()[0]
        
        # FailedIP
        cursor.execute(f'''
            SELECT source_ip, COUNT(*) as cnt FROM {table_name}
            WHERE {time_cond} AND source_ip IS NOT NULL AND source_ip != ''
            GROUP BY source_ip
        ''', time_params)
        for ip, cnt in cursor.fetchall():
            agg['failed_ips'][ip] = agg['failed_ips'].get(ip, 0) + cnt
        
        # Failed用户
        cursor.execute(f'''
            SELECT user, COUNT(*) as cnt FROM {table_name}
            WHERE {time_cond} AND user IS NOT NULL AND user != ''
            GROUP BY user
        ''', time_params)
        for user, cnt in cursor.fetchall():
            agg['failed_users'][user] = agg['failed_users'].get(user, 0) + cnt
    
    def _collect_wtmp_stats(self, cursor, table_name, time_cond, time_params, stats, agg):
        """收集wtmp统计 - USER_PROCESS是成功登录"""
        # Success登录
        cursor.execute(f'''
            SELECT COUNT(*) FROM {table_name}
            WHERE {time_cond} AND event_type = 'USER_PROCESS'
        ''', time_params)
        stats.login_success += cursor.fetchone()[0]
        
        # Success用户
        cursor.execute(f'''
            SELECT user, COUNT(*) as cnt FROM {table_name}
            WHERE {time_cond} AND event_type = 'USER_PROCESS' 
              AND user IS NOT NULL AND user != ''
            GROUP BY user
        ''', time_params)
        for user, cnt in cursor.fetchall():
            agg['success_users'][user] = agg['success_users'].get(user, 0) + cnt
    
    def _collect_lastlog_stats(self, cursor, table_name, time_cond, time_params, stats, agg):
        """收集lastlog统计"""
        cursor.execute(f'''
            SELECT user, COUNT(*) as cnt FROM {table_name}
            WHERE {time_cond} AND user IS NOT NULL AND user != ''
            GROUP BY user
        ''', time_params)
        for user, cnt in cursor.fetchall():
            agg['success_users'][user] = agg['success_users'].get(user, 0) + cnt
    
    def _collect_secure_stats(self, cursor, table_name, time_cond, time_params, stats, agg):
        """收集secure/auth统计"""
        # 使用单个查询获取多个计数
        cursor.execute(f'''
            SELECT 
                SUM(CASE WHEN event_type LIKE 'SSH_ACCEPTED%' THEN 1 ELSE 0 END) as success,
                SUM(CASE WHEN event_type LIKE 'SSH_FAILED%' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN event_type IN ('SSH_INVALID_USER', 'SSH_PREAUTH_INVALID_USER') THEN 1 ELSE 0 END) as invalid,
                SUM(CASE WHEN event_type = 'SUDO_COMMAND' THEN 1 ELSE 0 END) as sudo_ok,
                SUM(CASE WHEN event_type = 'SUDO_NOT_IN_SUDOERS' THEN 1 ELSE 0 END) as sudo_denied
            FROM {table_name}
            WHERE {time_cond}
        ''', time_params)
        row = cursor.fetchone()
        if row:
            stats.login_success += row[0] or 0
            stats.login_failed += row[1] or 0
            stats.invalid_user_attempts += row[2] or 0
            stats.sudo_success += row[3] or 0
            stats.sudo_denied += row[4] or 0
        
        # FailedIP
        cursor.execute(f'''
            SELECT source_ip, COUNT(*) as cnt FROM {table_name}
            WHERE {time_cond} AND result = 'failed' 
              AND source_ip IS NOT NULL AND source_ip != ''
            GROUP BY source_ip
        ''', time_params)
        for ip, cnt in cursor.fetchall():
            agg['failed_ips'][ip] = agg['failed_ips'].get(ip, 0) + cnt
        
        # Failed用户
        cursor.execute(f'''
            SELECT user, COUNT(*) as cnt FROM {table_name}
            WHERE {time_cond} AND result = 'failed' 
              AND user IS NOT NULL AND user != ''
            GROUP BY user
        ''', time_params)
        for user, cnt in cursor.fetchall():
            agg['failed_users'][user] = agg['failed_users'].get(user, 0) + cnt
        
        # Success用户
        cursor.execute(f'''
            SELECT user, COUNT(*) as cnt FROM {table_name}
            WHERE {time_cond} AND result = 'success' 
              AND user IS NOT NULL AND user != ''
            GROUP BY user
        ''', time_params)
        for user, cnt in cursor.fetchall():
            agg['success_users'][user] = agg['success_users'].get(user, 0) + cnt
        
        # Sudo用户
        cursor.execute(f'''
            SELECT user, COUNT(*) as cnt FROM {table_name}
            WHERE {time_cond} AND event_type LIKE 'SUDO%'
              AND user IS NOT NULL AND user != ''
            GROUP BY user
        ''', time_params)
        for user, cnt in cursor.fetchall():
            agg['sudo_users'][user] = agg['sudo_users'].get(user, 0) + cnt
    
    def _collect_event_distribution(self, cursor, table_name, time_cond, time_params, agg):
        """收集事件类型分布"""
        cursor.execute(f'''
            SELECT event_type, COUNT(*) as cnt FROM {table_name}
            WHERE {time_cond} AND event_type IS NOT NULL AND event_type != ''
            GROUP BY event_type
        ''', time_params)
        for event_type, cnt in cursor.fetchall():
            agg['event_types'][event_type] = agg['event_types'].get(event_type, 0) + cnt
    
    def _collect_hourly_timeline(self, cursor, table_name, log_type, time_cond, time_params, agg):
        """收集时间趋势"""
        # 根据日志类型确定成功/失败的判断条件
        if log_type == 'btmp':
            success_cond = "0"  # btmp没有成功
            failed_cond = "1"   # 全是失败
        elif log_type == 'wtmp':
            success_cond = "CASE WHEN event_type = 'USER_PROCESS' THEN 1 ELSE 0 END"
            failed_cond = "0"
        else:
            success_cond = "CASE WHEN result = 'success' THEN 1 ELSE 0 END"
            failed_cond = "CASE WHEN result = 'failed' THEN 1 ELSE 0 END"
        
        cursor.execute(f'''
            SELECT strftime('%Y-%m-%d %H:00', datetime(timestamp_unix, 'unixepoch')) as hour,
                   SUM({success_cond}) as success,
                   SUM({failed_cond}) as failed
            FROM {table_name}
            WHERE {time_cond}
            GROUP BY hour
        ''', time_params)
        
        for hour, success, failed in cursor.fetchall():
            if hour not in agg['hourly_data']:
                agg['hourly_data'][hour] = {'hour': hour, 'success': 0, 'failed': 0}
            agg['hourly_data'][hour]['success'] += success or 0
            agg['hourly_data'][hour]['failed'] += failed or 0
    
    def _finalize_aggregators(self, stats: SecurityStats, agg: Dict):
        """将聚合数据转换为排序后的列表"""
        stats.top_failed_ips = [
            {"ip": k, "count": v} 
            for k, v in sorted(agg['failed_ips'].items(), key=lambda x: -x[1])[:50]
        ]
        stats.top_failed_users = [
            {"user": k, "count": v} 
            for k, v in sorted(agg['failed_users'].items(), key=lambda x: -x[1])[:50]
        ]
        stats.top_success_users = [
            {"user": k, "count": v} 
            for k, v in sorted(agg['success_users'].items(), key=lambda x: -x[1])[:50]
        ]
        stats.top_sudo_users = [
            {"user": k, "count": v} 
            for k, v in sorted(agg['sudo_users'].items(), key=lambda x: -x[1])[:50]
        ]
        stats.event_type_distribution = [
            {"type": k, "count": v} 
            for k, v in sorted(agg['event_types'].items(), key=lambda x: -x[1])
        ]
        stats.hourly_timeline = sorted(agg['hourly_data'].values(), key=lambda x: x['hour'])
    
    def get_aggregation_summary(self, host_id: str, cache_manager) -> List[Dict[str, Any]]:
        """
        获取主机的所有汇聚摘要
        
        Args:
            host_id: 主机ID
            cache_manager: CacheManager实例
            
        Returns:
            [
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
        """
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            # 获取该主机的所有表
            host_hash = self._get_host_hash(host_id)
            cursor.execute('''
                SELECT DISTINCT table_name, log_type
                FROM file_cache_status
                WHERE host_id = ?
                ORDER BY log_type
            ''', (host_id,))
            
            summaries = []
            
            for table_name, log_type in cursor.fetchall():
                # 获取该表的汇聚信息
                agg_info = cache_manager.get_file_aggregation_info(log_type, host_id)
                
                if agg_info["file_count"] > 0:
                    # 生成显示文本
                    aggregation_display = f"{agg_info['file_count']}个文件 → 1个表"
                    
                    summaries.append({
                        "log_type": log_type,
                        "table_name": table_name,
                        "file_count": agg_info["file_count"],
                        "total_events": agg_info["total_events"],
                        "aggregation_display": aggregation_display,
                        "files": agg_info["files"]
                    })
            
            conn.close()
            
            return summaries
            
        except Exception as e:
            print(f"[StatisticsService] 获取汇聚摘要失败: {e}")
            return []
    
    def get_source_info_for_filter(self, host_id: str, filter_type: str, 
                                   filter_value: str, cache_manager) -> Dict[str, Any]:
        """
        获取过滤查询的来源信息
        用于EventDetailPanel显示
        
        Args:
            host_id: 主机ID
            filter_type: 过滤类型 (如 'user', 'ip', 'event_type')
            filter_value: 过滤值
            cache_manager: CacheManager实例
            
        Returns:
            {
                "table_count": 3,
                "tables": [
                    {
                        "name": "events_secure_xxx",
                        "type": "secure",
                        "file_count": 2,
                        "files": [...]
                    },
                    ...
                ],
                "total_files": 5,
                "total_events": 12345
            }
        """
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            # 获取该主机的所有表
            cursor.execute('''
                SELECT DISTINCT table_name, log_type
                FROM file_cache_status
                WHERE host_id = ?
                ORDER BY log_type
            ''', (host_id,))
            
            tables_info = []
            total_files = 0
            total_events = 0
            
            for table_name, log_type in cursor.fetchall():
                # 获取该表的汇聚信息
                agg_info = cache_manager.get_file_aggregation_info(log_type, host_id)
                
                if agg_info["file_count"] > 0:
                    tables_info.append({
                        "name": table_name,
                        "type": log_type,
                        "file_count": agg_info["file_count"],
                        "files": agg_info["files"]
                    })
                    
                    total_files += agg_info["file_count"]
                    total_events += agg_info["total_events"]
            
            conn.close()
            
            return {
                "table_count": len(tables_info),
                "tables": tables_info,
                "total_files": total_files,
                "total_events": total_events
            }
            
        except Exception as e:
            print(f"[StatisticsService] 获取source_info失败: {e}")
            return {
                "table_count": 0,
                "tables": [],
                "total_files": 0,
                "total_events": 0
            }


    def get_filtered_events(self, host_id: str, filter_type: str, filter_value: str,
                           time_range: str = 'all', search_term: str = None, 
                           date_start: str = None, date_end: str = None, 
                           result_filter: str = None, event_type_filter: str = None, 
                           page: int = 1, page_size: int = 50, 
                           sort_field: str = 'timestamp_unix',
                           sort_direction: str = 'desc',
                           cache_manager = None) -> Dict[str, Any]:
        """
        获取按IP或用户过滤的事件列表
        
        Args:
            host_id: 主机ID
            filter_type: 过滤类型 ('ip' 或 'user')
            filter_value: 过滤值 (IP地址或用户名)
            time_range: 时间范围 ('1h', '6h', '24h', '7d', '30d', 'all')
            search_term: 搜索关键词
            date_start: 开始日期 (格式: YYYY-MM-DDTHH:MM)
            date_end: 结束日期
            result_filter: 结果过滤 ('success' 或 'failed')
            event_type_filter: 事件类型过滤
            page: 页码
            page_size: 每页大小
            sort_field: 排序字段
            sort_direction: 排序方向
        """
        events = []
        timeline_data = {}
        event_types_set = set()
        total_count = 0
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            tables = self._get_security_tables(cursor, host_id)
            
            if not tables:
                conn.close()
                return {
                    "success": True,
                    "events": [],
                    "pagination": {"page": 1, "page_size": page_size, "total_count": 0, "total_pages": 0},
                    "timeline": [],
                    "event_types": [],
                    "source_info": {
                        "table_count": 0,
                        "tables": []
                    }
                }
            
            # 首先获取所有可用的事件类型（不受过滤条件限制）
            all_event_types = set()
            for table_name, log_type in tables:
                try:
                    cursor.execute(f'''
                        SELECT DISTINCT event_type FROM {table_name}
                        WHERE event_type IS NOT NULL AND event_type != ''
                    ''')
                    for (event_type,) in cursor.fetchall():
                        all_event_types.add(event_type)
                except sqlite3.OperationalError:
                    continue
            
            # 构建过滤条件
            filter_field = 'source_ip' if filter_type == 'ip' else 'user'
            
            # Parse time范围
            min_time = self._parse_time_range(time_range)
            
            all_events = []
            
            for table_name, log_type in tables:
                # 构建WHERE条件
                conditions = [f"{filter_field} = ?"]
                params = [filter_value]
                
                # 时间范围过滤（优先使用time_range）
                if min_time:
                    conditions.append("timestamp_unix >= ?")
                    params.append(min_time)
                
                # 日期范围（如果没有time_range，使用自定义日期）
                if not min_time and date_start:
                    conditions.append("timestamp_str >= ?")
                    params.append(date_start.replace('T', ' '))
                if not min_time and date_end:
                    conditions.append("timestamp_str <= ?")
                    params.append(date_end.replace('T', ' '))
                
                # 结果过滤
                if result_filter:
                    conditions.append("result = ?")
                    params.append(result_filter)
                
                # 事件类型过滤
                if event_type_filter:
                    conditions.append("event_type = ?")
                    params.append(event_type_filter)
                
                # 搜索关键词
                if search_term:
                    conditions.append("(message LIKE ? OR event_name LIKE ? OR hostname LIKE ?)")
                    search_pattern = f"%{search_term}%"
                    params.extend([search_pattern, search_pattern, search_pattern])
                
                where_clause = " AND ".join(conditions)
                
                # 查询事件
                try:
                    cursor.execute(f'''
                        SELECT timestamp_str, timestamp_unix, event_type, event_name,
                               user, source_ip, result, message, hostname, process
                        FROM {table_name}
                        WHERE {where_clause}
                    ''', params)
                    
                    for row in cursor.fetchall():
                        event = dict(row)
                        all_events.append(event)
                        
                        # 收集事件类型
                        if event.get('event_type'):
                            event_types_set.add(event['event_type'])
                        
                        # 收集时间线数据
                        ts = event.get('timestamp_str', '')
                        if ts and len(ts) >= 13:
                            hour_key = ts[:13] + ':00'
                            timeline_data[hour_key] = timeline_data.get(hour_key, 0) + 1
                            
                except sqlite3.OperationalError:
                    # 表可能没有某些字段，跳过
                    continue
            
            conn.close()
            
            # 排序
            reverse = sort_direction == 'desc'
            if sort_field == 'timestamp_unix':
                all_events.sort(key=lambda x: x.get('timestamp_unix') or 0, reverse=reverse)
            elif sort_field == 'event_type':
                all_events.sort(key=lambda x: x.get('event_type') or '', reverse=reverse)
            else:
                all_events.sort(key=lambda x: x.get(sort_field) or '', reverse=reverse)
            
            # 分页
            total_count = len(all_events)
            total_pages = max(1, (total_count + page_size - 1) // page_size)
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            events = all_events[start_idx:end_idx]
            
            # 转换时间线数据
            timeline = [
                {"hour": k, "count": v}
                for k, v in sorted(timeline_data.items())
            ][-48:]  # 最近48小时
            
            # 获取增强的source_info
            if cache_manager:
                source_info = self.get_source_info_for_filter(host_id, filter_type, filter_value, cache_manager)
            else:
                # 向后兼容：如果没有cache_manager，使用简单版本
                source_info = {
                    "table_count": len(tables),
                    "tables": [{"name": t[0], "type": t[1]} for t in tables],
                    "total_files": 0,
                    "total_events": 0
                }
            
            return {
                "success": True,
                "events": events,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_count": total_count,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1
                },
                "timeline": timeline,
                "event_types": sorted(list(all_event_types)),  # 使用所有可用的事件类型
                "source_info": source_info
            }
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}


    def get_filtered_audit_events(self, host_id: str, filter_type: str, filter_value: str,
                                  time_range: str = 'all', search_term: str = None, 
                                  date_start: str = None, date_end: str = None, 
                                  result_filter: str = None, event_type_filter: str = None, 
                                  page: int = 1, page_size: int = 50, 
                                  sort_field: str = 'timestamp_unix',
                                  sort_direction: str = 'desc',
                                  cache_manager = None) -> Dict[str, Any]:
        """
        获取按IP或用户过滤的审计事件列表
        
        Args:
            host_id: 主机ID
            filter_type: 过滤类型 ('ip' 或 'user')
            filter_value: 过滤值 (IP地址或用户名)
            time_range: 时间范围 ('1h', '6h', '24h', '7d', '30d', 'all')
            search_term: 搜索关键词
            date_start: 开始日期 (格式: YYYY-MM-DDTHH:MM)
            date_end: 结束日期
            result_filter: 结果过滤 ('success' 或 'failed')
            event_type_filter: 事件类型过滤 (audit_type)
            page: 页码
            page_size: 每页大小
            sort_field: 排序字段
            sort_direction: 排序方向
        """
        events = []
        timeline_data = {}
        event_types_set = set()
        total_count = 0
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            tables = self._get_audit_tables(cursor, host_id)
            
            if not tables:
                conn.close()
                return {
                    "success": True,
                    "events": [],
                    "pagination": {"page": 1, "page_size": page_size, "total_count": 0, "total_pages": 0},
                    "timeline": [],
                    "event_types": [],
                    "source_info": {
                        "table_count": 0,
                        "tables": []
                    }
                }
            
            # 首先获取所有可用的事件类型（不受过滤条件限制）
            all_event_types = set()
            for table_name, log_type in tables:
                try:
                    cursor.execute(f'''
                        SELECT DISTINCT audit_type FROM {table_name}
                        WHERE audit_type IS NOT NULL AND audit_type != ''
                    ''')
                    for (event_type,) in cursor.fetchall():
                        all_event_types.add(event_type)
                except sqlite3.OperationalError:
                    continue
            
            # 构建过滤条件 - 审计日志使用 source_ip 和 user 字段
            filter_field = 'source_ip' if filter_type == 'ip' else 'user'
            
            # Parse time范围
            min_time = self._parse_time_range(time_range)
            
            all_events = []
            
            for table_name, log_type in tables:
                # 构建WHERE条件
                conditions = [f"{filter_field} = ?"]
                params = [filter_value]
                
                # 时间范围过滤（优先使用time_range）
                if min_time:
                    conditions.append("timestamp_unix >= ?")
                    params.append(min_time)
                
                # 日期范围（如果没有time_range，使用自定义日期）
                if not min_time and date_start:
                    conditions.append("timestamp_str >= ?")
                    params.append(date_start.replace('T', ' '))
                if not min_time and date_end:
                    conditions.append("timestamp_str <= ?")
                    params.append(date_end.replace('T', ' '))
                
                # 结果过滤
                if result_filter:
                    conditions.append("result = ?")
                    params.append(result_filter)
                
                # 事件类型过滤 - 审计日志使用 audit_type
                if event_type_filter:
                    conditions.append("audit_type = ?")
                    params.append(event_type_filter)
                
                # 搜索关键词
                if search_term:
                    conditions.append("(event_name LIKE ? OR operation LIKE ? OR exe LIKE ? OR terminal LIKE ?)")
                    search_pattern = f"%{search_term}%"
                    params.extend([search_pattern, search_pattern, search_pattern, search_pattern])
                
                where_clause = " AND ".join(conditions)
                
                # 查询事件 - 审计日志特有的字段
                try:
                    cursor.execute(f'''
                        SELECT timestamp_str, timestamp_unix, audit_type as event_type, event_name,
                               user, source_ip, result, operation as message, hostname, exe as process,
                               terminal, pid, session_id
                        FROM {table_name}
                        WHERE {where_clause}
                    ''', params)
                    
                    for row in cursor.fetchall():
                        event = dict(row)
                        all_events.append(event)
                        
                        # 收集事件类型
                        if event.get('event_type'):
                            event_types_set.add(event['event_type'])
                        
                        # 收集时间线数据
                        ts = event.get('timestamp_str', '')
                        if ts and len(ts) >= 13:
                            hour_key = ts[:13] + ':00'
                            timeline_data[hour_key] = timeline_data.get(hour_key, 0) + 1
                            
                except sqlite3.OperationalError as e:
                    print(f"[StatisticsService] 查询审计表失败 {table_name}: {e}")
                    continue
            
            conn.close()
            
            # 排序
            reverse = sort_direction == 'desc'
            if sort_field == 'timestamp_unix':
                all_events.sort(key=lambda x: x.get('timestamp_unix') or 0, reverse=reverse)
            elif sort_field == 'event_type':
                all_events.sort(key=lambda x: x.get('event_type') or '', reverse=reverse)
            else:
                all_events.sort(key=lambda x: x.get(sort_field) or '', reverse=reverse)
            
            # 分页
            total_count = len(all_events)
            total_pages = max(1, (total_count + page_size - 1) // page_size)
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            events = all_events[start_idx:end_idx]
            
            # 转换时间线数据
            timeline = [
                {"hour": k, "count": v}
                for k, v in sorted(timeline_data.items())
            ][-48:]  # 最近48小时
            
            # 获取增强的source_info
            source_info = {
                "table_count": len(tables),
                "tables": [{"name": t[0], "type": t[1]} for t in tables],
                "total_files": 0,
                "total_events": 0
            }
            
            return {
                "success": True,
                "events": events,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_count": total_count,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1
                },
                "timeline": timeline,
                "event_types": sorted(list(all_event_types)),
                "source_info": source_info
            }
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
