#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
审计日志统计服务

提供审计日志的统计分析功能:
- 认证统计（成功/失败/失败率）
- 登录统计（成功/失败/唯一用户/唯一IP）
- 会话统计（活跃会话/今日会话）
- 异常统计（USER_ERR/失败事件）
- Top N查询（用户活动/来源IP）
- 分布统计（事件类型/时间趋势/终端）

Requirements: 7.1, 7.3, 7.4
"""

import os
import sys
import sqlite3
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


@dataclass
class AuditStats:
    """审计统计数据结构"""
    # 认证统计
    auth_success: int = 0
    auth_failed: int = 0
    auth_failure_rate: float = 0.0
    
    # 登录统计
    login_success: int = 0
    login_failed: int = 0
    unique_users: int = 0
    unique_ips: int = 0
    
    # 会话统计
    session_started: int = 0
    session_ended: int = 0
    active_sessions: int = 0
    today_sessions: int = 0
    
    # 异常统计
    user_errors: int = 0
    failed_events: int = 0
    
    # Top列表
    top_users: List[Dict[str, Any]] = field(default_factory=list)
    top_ips: List[Dict[str, Any]] = field(default_factory=list)
    top_failed_users: List[Dict[str, Any]] = field(default_factory=list)
    top_failed_ips: List[Dict[str, Any]] = field(default_factory=list)
    
    # 分布数据
    event_type_distribution: List[Dict[str, Any]] = field(default_factory=list)
    hourly_timeline: List[Dict[str, Any]] = field(default_factory=list)
    terminal_distribution: List[Dict[str, Any]] = field(default_factory=list)
    exe_distribution: List[Dict[str, Any]] = field(default_factory=list)
    
    # 新增：进程和操作相关统计
    op_distribution: List[Dict[str, Any]] = field(default_factory=list)  # 操作类型分布
    subj_distribution: List[Dict[str, Any]] = field(default_factory=list)  # SELinux主体分布
    grantors_distribution: List[Dict[str, Any]] = field(default_factory=list)  # PAM授权模块分布
    
    # 新增：加密操作统计
    crypto_kind_distribution: List[Dict[str, Any]] = field(default_factory=list)  # 密钥类型分布
    crypto_direction_distribution: List[Dict[str, Any]] = field(default_factory=list)  # 加密方向分布
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "auth_success": self.auth_success,
            "auth_failed": self.auth_failed,
            "auth_failure_rate": self.auth_failure_rate,
            "login_success": self.login_success,
            "login_failed": self.login_failed,
            "unique_users": self.unique_users,
            "unique_ips": self.unique_ips,
            "session_started": self.session_started,
            "session_ended": self.session_ended,
            "active_sessions": self.active_sessions,
            "today_sessions": self.today_sessions,
            "user_errors": self.user_errors,
            "failed_events": self.failed_events,
            "top_users": self.top_users,
            "top_ips": self.top_ips,
            "top_failed_users": self.top_failed_users,
            "top_failed_ips": self.top_failed_ips,
            "event_type_distribution": self.event_type_distribution,
            "hourly_timeline": self.hourly_timeline,
            "terminal_distribution": self.terminal_distribution,
            "exe_distribution": self.exe_distribution,
            # 新增统计
            "op_distribution": self.op_distribution,
            "subj_distribution": self.subj_distribution,
            "grantors_distribution": self.grantors_distribution,
            "crypto_kind_distribution": self.crypto_kind_distribution,
            "crypto_direction_distribution": self.crypto_direction_distribution,
        }


class AuditStatisticsService:
    """审计日志统计服务"""
    
    # 事件分类映射
    EVENT_CATEGORIES = {
        'security_auth': ['USER_AUTH', 'USER_LOGIN', 'USER_LOGOUT', 'LOGIN', 'USER_ERR'],
        'credential': ['CRED_ACQ', 'CRED_DISP', 'CRED_REFR'],
        'session': ['USER_START', 'USER_END', 'USER_ACCT'],
        'crypto': ['CRYPTO_KEY_USER', 'CRYPTO_SESSION'],
        'service': ['SERVICE_START', 'SERVICE_STOP', 'DAEMON_START', 'DAEMON_END'],
    }
    
    # 分类中文名映射
    CATEGORY_NAMES = {
        'security_auth': '安全认证',
        'credential': '凭证管理',
        'session': '会话管理',
        'crypto': '加密操作',
        'service': '服务管理',
        'other': '其他',
    }
    
    def __init__(self, db_path: str):
        """
        初始化统计服务
        
        Args:
            db_path: SQLite数据库路径
        """
        self.db_path = db_path
    
    def _get_table_name(self, host_id: str) -> str:
        """生成审计日志表名"""
        host_hash = hashlib.md5(host_id.encode()).hexdigest()[:8]
        return f"events_audit_{host_hash}"
    
    def _get_time_condition(self, time_range: str) -> tuple:
        """
        获取时间范围条件
        
        Args:
            time_range: 时间范围 ('1h', '6h', '24h', '7d', '30d', 'all')
            
        Returns:
            (where_clause, params)
        """
        if time_range == 'all':
            return "", []
        
        now = datetime.now()
        
        if time_range == '1h':
            cutoff = now - timedelta(hours=1)
        elif time_range == '6h':
            cutoff = now - timedelta(hours=6)
        elif time_range == '24h':
            cutoff = now - timedelta(hours=24)
        elif time_range == '7d':
            cutoff = now - timedelta(days=7)
        elif time_range == '30d':
            cutoff = now - timedelta(days=30)
        else:
            return "", []
        
        cutoff_unix = int(cutoff.timestamp())
        return "timestamp_unix >= ?", [cutoff_unix]

    def _table_exists(self, cursor, table_name: str) -> bool:
        """检查表是否存在"""
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,)
        )
        return cursor.fetchone() is not None
    
    def get_auth_statistics(self, cursor, table_name: str, 
                           time_cond: str, params: list) -> Dict[str, Any]:
        """
        获取认证统计
        
        统计USER_AUTH事件的成功/失败数量
        
        Returns:
            {
                "success": 123,
                "failed": 45,
                "failure_rate": 26.8
            }
        """
        where = f"audit_type = 'USER_AUTH'"
        if time_cond:
            where += f" AND {time_cond}"
        
        # Success数
        cursor.execute(f"""
            SELECT COUNT(*) FROM {table_name}
            WHERE {where} AND result = 'success'
        """, params)
        success = cursor.fetchone()[0]
        
        # Failed数
        cursor.execute(f"""
            SELECT COUNT(*) FROM {table_name}
            WHERE {where} AND result = 'failed'
        """, params)
        failed = cursor.fetchone()[0]
        
        total = success + failed
        failure_rate = (failed / total * 100) if total > 0 else 0.0
        
        return {
            "success": success,
            "failed": failed,
            "failure_rate": round(failure_rate, 2)
        }
    
    def get_login_statistics(self, cursor, table_name: str,
                            time_cond: str, params: list) -> Dict[str, Any]:
        """
        获取登录统计
        
        统计USER_LOGIN事件的成功/失败数量，唯一用户数和唯一IP数
        
        Returns:
            {
                "success": 100,
                "failed": 20,
                "unique_users": 15,
                "unique_ips": 8
            }
        """
        where = f"audit_type = 'USER_LOGIN'"
        if time_cond:
            where += f" AND {time_cond}"
        
        # Success数
        cursor.execute(f"""
            SELECT COUNT(*) FROM {table_name}
            WHERE {where} AND result = 'success'
        """, params)
        success = cursor.fetchone()[0]
        
        # Failed数
        cursor.execute(f"""
            SELECT COUNT(*) FROM {table_name}
            WHERE {where} AND result = 'failed'
        """, params)
        failed = cursor.fetchone()[0]
        
        # 唯一用户数
        cursor.execute(f"""
            SELECT COUNT(DISTINCT user) FROM {table_name}
            WHERE {where} AND user IS NOT NULL AND user != ''
        """, params)
        unique_users = cursor.fetchone()[0]
        
        # 唯一IP数
        cursor.execute(f"""
            SELECT COUNT(DISTINCT source_ip) FROM {table_name}
            WHERE {where} AND source_ip IS NOT NULL AND source_ip != ''
        """, params)
        unique_ips = cursor.fetchone()[0]
        
        return {
            "success": success,
            "failed": failed,
            "unique_users": unique_users,
            "unique_ips": unique_ips
        }
    
    def get_session_statistics(self, cursor, table_name: str,
                              time_cond: str, params: list) -> Dict[str, Any]:
        """
        获取会话统计
        
        统计USER_START和USER_END事件，计算活跃会话数和今日会话数
        
        Returns:
            {
                "started": 150,
                "ended": 140,
                "active": 10,
                "today": 50
            }
        """
        # 会话开始数
        where_start = "audit_type = 'USER_START'"
        if time_cond:
            where_start += f" AND {time_cond}"
        
        cursor.execute(f"""
            SELECT COUNT(*) FROM {table_name}
            WHERE {where_start}
        """, params)
        started = cursor.fetchone()[0]
        
        # 会话结束数
        where_end = "audit_type = 'USER_END'"
        if time_cond:
            where_end += f" AND {time_cond}"
        
        cursor.execute(f"""
            SELECT COUNT(*) FROM {table_name}
            WHERE {where_end}
        """, params)
        ended = cursor.fetchone()[0]
        
        # 活跃会话数（开始 - 结束）
        active = max(0, started - ended)
        
        # 今日会话数
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_unix = int(today_start.timestamp())
        
        cursor.execute(f"""
            SELECT COUNT(*) FROM {table_name}
            WHERE audit_type = 'USER_START' AND timestamp_unix >= ?
        """, [today_unix])
        today = cursor.fetchone()[0]
        
        return {
            "started": started,
            "ended": ended,
            "active": active,
            "today": today
        }
    
    def get_error_statistics(self, cursor, table_name: str,
                            time_cond: str, params: list) -> Dict[str, Any]:
        """
        获取异常统计
        
        统计USER_ERR事件数量和所有失败事件总数
        
        Returns:
            {
                "user_errors": 10,
                "failed_events": 50
            }
        """
        # USER_ERR数量
        where_err = "audit_type = 'USER_ERR'"
        if time_cond:
            where_err += f" AND {time_cond}"
        
        cursor.execute(f"""
            SELECT COUNT(*) FROM {table_name}
            WHERE {where_err}
        """, params)
        user_errors = cursor.fetchone()[0]
        
        # 所有失败事件
        where_failed = "result = 'failed'"
        if time_cond:
            where_failed += f" AND {time_cond}"
        
        cursor.execute(f"""
            SELECT COUNT(*) FROM {table_name}
            WHERE {where_failed}
        """, params)
        failed_events = cursor.fetchone()[0]
        
        return {
            "user_errors": user_errors,
            "failed_events": failed_events
        }

    def get_top_users(self, cursor, table_name: str,
                     time_cond: str, params: list, limit: int = 10) -> List[Dict[str, Any]]:
        """
        获取用户活动Top N
        
        Returns:
            [{"user": "root", "count": 100}, ...]
        """
        where = "user IS NOT NULL AND user != ''"
        if time_cond:
            where += f" AND {time_cond}"
        
        cursor.execute(f"""
            SELECT user, COUNT(*) as count
            FROM {table_name}
            WHERE {where}
            GROUP BY user
            ORDER BY count DESC
            LIMIT ?
        """, params + [limit])
        
        return [{"user": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    def get_top_ips(self, cursor, table_name: str,
                   time_cond: str, params: list, limit: int = 10) -> List[Dict[str, Any]]:
        """
        获取来源IP Top N
        
        Returns:
            [{"ip": "10.0.0.1", "count": 50}, ...]
        """
        where = "source_ip IS NOT NULL AND source_ip != ''"
        if time_cond:
            where += f" AND {time_cond}"
        
        cursor.execute(f"""
            SELECT source_ip, COUNT(*) as count
            FROM {table_name}
            WHERE {where}
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT ?
        """, params + [limit])
        
        return [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    def get_top_failed_users(self, cursor, table_name: str,
                            time_cond: str, params: list, limit: int = 10) -> List[Dict[str, Any]]:
        """
        获取失败用户Top N
        
        Returns:
            [{"user": "admin", "count": 20}, ...]
        """
        where = "user IS NOT NULL AND user != '' AND result = 'failed'"
        if time_cond:
            where += f" AND {time_cond}"
        
        cursor.execute(f"""
            SELECT user, COUNT(*) as count
            FROM {table_name}
            WHERE {where}
            GROUP BY user
            ORDER BY count DESC
            LIMIT ?
        """, params + [limit])
        
        return [{"user": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    def get_top_failed_ips(self, cursor, table_name: str,
                          time_cond: str, params: list, limit: int = 10) -> List[Dict[str, Any]]:
        """
        获取失败IP Top N
        
        Returns:
            [{"ip": "192.168.1.100", "count": 15}, ...]
        """
        where = "source_ip IS NOT NULL AND source_ip != '' AND result = 'failed'"
        if time_cond:
            where += f" AND {time_cond}"
        
        cursor.execute(f"""
            SELECT source_ip, COUNT(*) as count
            FROM {table_name}
            WHERE {where}
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT ?
        """, params + [limit])
        
        return [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    def get_event_distribution(self, cursor, table_name: str,
                              time_cond: str, params: list) -> List[Dict[str, Any]]:
        """
        获取事件类型分布
        
        Returns:
            [{"type": "USER_AUTH", "name": "用户认证", "count": 100}, ...]
        """
        where = "1=1"
        if time_cond:
            where = time_cond
        
        cursor.execute(f"""
            SELECT audit_type, event_name, COUNT(*) as count
            FROM {table_name}
            WHERE {where}
            GROUP BY audit_type
            ORDER BY count DESC
        """, params)
        
        return [
            {"type": row[0], "name": row[1] or row[0], "count": row[2]}
            for row in cursor.fetchall()
        ]
    
    def get_hourly_timeline(self, cursor, table_name: str,
                           time_cond: str, params: list) -> List[Dict[str, Any]]:
        """
        获取按小时统计的时间趋势
        
        Returns:
            [{"hour": "2024-01-01 10:00", "success": 50, "failed": 5, "total": 55}, ...]
        """
        where = "1=1"
        if time_cond:
            where = time_cond
        
        # 使用SQLite的datetime函数按小时分组
        cursor.execute(f"""
            SELECT 
                strftime('%Y-%m-%d %H:00', datetime(timestamp_unix, 'unixepoch', 'localtime')) as hour,
                SUM(CASE WHEN result = 'success' THEN 1 ELSE 0 END) as success,
                SUM(CASE WHEN result = 'failed' THEN 1 ELSE 0 END) as failed,
                COUNT(*) as total
            FROM {table_name}
            WHERE {where}
            GROUP BY hour
            ORDER BY hour DESC
            LIMIT 168
        """, params)  # 最多返回7天的小时数据
        
        results = []
        for row in cursor.fetchall():
            results.append({
                "hour": row[0],
                "success": row[1],
                "failed": row[2],
                "total": row[3]
            })
        
        # 按时间正序返回
        return list(reversed(results))
    
    def get_terminal_distribution(self, cursor, table_name: str,
                                  time_cond: str, params: list) -> List[Dict[str, Any]]:
        """
        获取终端分布
        
        Returns:
            [{"terminal": "ssh", "count": 200}, ...]
        """
        where = "terminal IS NOT NULL AND terminal != ''"
        if time_cond:
            where += f" AND {time_cond}"
        
        cursor.execute(f"""
            SELECT terminal, COUNT(*) as count
            FROM {table_name}
            WHERE {where}
            GROUP BY terminal
            ORDER BY count DESC
            LIMIT 20
        """, params)
        
        return [{"terminal": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    def get_exe_distribution(self, cursor, table_name: str,
                            time_cond: str, params: list, limit: int = 10) -> List[Dict[str, Any]]:
        """
        获取执行程序分布Top N
        
        Returns:
            [{"exe": "sshd", "count": 300}, ...]
        """
        where = "exe IS NOT NULL AND exe != ''"
        if time_cond:
            where += f" AND {time_cond}"
        
        # 使用exe_short字段（程序短名）
        cursor.execute(f"""
            SELECT 
                CASE 
                    WHEN exe LIKE '%/%' THEN substr(exe, instr(exe, '/') + length(exe) - length(replace(exe, '/', '')) + 1)
                    ELSE exe
                END as exe_name,
                COUNT(*) as count
            FROM {table_name}
            WHERE {where}
            GROUP BY exe_name
            ORDER BY count DESC
            LIMIT ?
        """, params + [limit])
        
        return [{"exe": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    def get_op_distribution(self, cursor, table_name: str,
                           time_cond: str, params: list, limit: int = 10) -> List[Dict[str, Any]]:
        """
        获取操作类型分布Top N
        
        Returns:
            [{"op": "PAM:authentication", "count": 200}, ...]
        """
        where = "operation IS NOT NULL AND operation != ''"
        if time_cond:
            where += f" AND {time_cond}"
        
        cursor.execute(f"""
            SELECT operation, COUNT(*) as count
            FROM {table_name}
            WHERE {where}
            GROUP BY operation
            ORDER BY count DESC
            LIMIT ?
        """, params + [limit])
        
        return [{"op": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    def _column_exists(self, cursor, table_name: str, column_name: str) -> bool:
        """检查列是否存在"""
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [row[1] for row in cursor.fetchall()]
        return column_name in columns
    
    def get_subj_distribution(self, cursor, table_name: str,
                             time_cond: str, params: list, limit: int = 5) -> List[Dict[str, Any]]:
        """
        获取SELinux主体分布Top N
        
        Returns:
            [{"subj": "unconfined_u:unconfined_r:unconfined_t:s0", "count": 500}, ...]
        """
        # Check column是否存在
        if not self._column_exists(cursor, table_name, 'subj'):
            return []
        
        where = "subj IS NOT NULL AND subj != ''"
        if time_cond:
            where += f" AND {time_cond}"
        
        try:
            cursor.execute(f"""
                SELECT subj, COUNT(*) as count
                FROM {table_name}
                WHERE {where}
                GROUP BY subj
                ORDER BY count DESC
                LIMIT ?
            """, params + [limit])
            
            return [{"subj": row[0], "count": row[1]} for row in cursor.fetchall()]
        except:
            return []
    
    def get_grantors_distribution(self, cursor, table_name: str,
                                  time_cond: str, params: list, limit: int = 5) -> List[Dict[str, Any]]:
        """
        获取PAM授权模块分布Top N
        
        Returns:
            [{"grantors": "pam_unix", "count": 300}, ...]
        """
        # Check column是否存在
        if not self._column_exists(cursor, table_name, 'grantors'):
            return []
        
        where = "grantors IS NOT NULL AND grantors != ''"
        if time_cond:
            where += f" AND {time_cond}"
        
        try:
            cursor.execute(f"""
                SELECT grantors, COUNT(*) as count
                FROM {table_name}
                WHERE {where}
                GROUP BY grantors
                ORDER BY count DESC
                LIMIT ?
            """, params + [limit])
            
            return [{"grantors": row[0], "count": row[1]} for row in cursor.fetchall()]
        except:
            return []
    
    def get_crypto_kind_distribution(self, cursor, table_name: str,
                                     time_cond: str, params: list) -> List[Dict[str, Any]]:
        """
        获取加密密钥类型分布
        
        Returns:
            [{"kind": "server", "count": 100}, {"kind": "session", "count": 50}, ...]
        """
        # Check column是否存在
        if not self._column_exists(cursor, table_name, 'crypto_kind'):
            return []
        
        where = "crypto_kind IS NOT NULL AND crypto_kind != ''"
        if time_cond:
            where += f" AND {time_cond}"
        
        try:
            cursor.execute(f"""
                SELECT crypto_kind, COUNT(*) as count
                FROM {table_name}
                WHERE {where}
                GROUP BY crypto_kind
                ORDER BY count DESC
            """, params)
            
            return [{"kind": row[0], "count": row[1]} for row in cursor.fetchall()]
        except:
            return []
    
    def get_crypto_direction_distribution(self, cursor, table_name: str,
                                          time_cond: str, params: list) -> List[Dict[str, Any]]:
        """
        获取加密方向分布
        
        Returns:
            [{"direction": "from-client", "count": 80}, {"direction": "both", "count": 40}, ...]
        """
        # Check column是否存在
        if not self._column_exists(cursor, table_name, 'crypto_direction'):
            return []
        
        where = "crypto_direction IS NOT NULL AND crypto_direction != ''"
        if time_cond:
            where += f" AND {time_cond}"
        
        try:
            cursor.execute(f"""
                SELECT crypto_direction, COUNT(*) as count
                FROM {table_name}
                WHERE {where}
                GROUP BY crypto_direction
                ORDER BY count DESC
            """, params)
            
            return [{"direction": row[0], "count": row[1]} for row in cursor.fetchall()]
        except:
            return []

    def get_audit_statistics(self, host_id: str, time_range: str = 'all') -> Dict[str, Any]:
        """
        获取审计日志统计
        
        Args:
            host_id: 主机ID
            time_range: 时间范围 ('1h', '6h', '24h', '7d', '30d', 'all')
            
        Returns:
            {
                "success": True,
                "statistics": AuditStats.to_dict()
            }
        """
        table_name = self._get_table_name(host_id)
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            # Check table是否存在
            if not self._table_exists(cursor, table_name):
                conn.close()
                return {
                    "success": False,
                    "error": f"审计日志表不存在: {table_name}"
                }
            
            # Get time条件
            time_cond, params = self._get_time_condition(time_range)
            
            # 创建统计对象
            stats = AuditStats()
            
            # 认证统计
            auth_stats = self.get_auth_statistics(cursor, table_name, time_cond, params)
            stats.auth_success = auth_stats["success"]
            stats.auth_failed = auth_stats["failed"]
            stats.auth_failure_rate = auth_stats["failure_rate"]
            
            # 登录统计
            login_stats = self.get_login_statistics(cursor, table_name, time_cond, params)
            stats.login_success = login_stats["success"]
            stats.login_failed = login_stats["failed"]
            stats.unique_users = login_stats["unique_users"]
            stats.unique_ips = login_stats["unique_ips"]
            
            # 会话统计
            session_stats = self.get_session_statistics(cursor, table_name, time_cond, params)
            stats.session_started = session_stats["started"]
            stats.session_ended = session_stats["ended"]
            stats.active_sessions = session_stats["active"]
            stats.today_sessions = session_stats["today"]
            
            # 异常统计
            error_stats = self.get_error_statistics(cursor, table_name, time_cond, params)
            stats.user_errors = error_stats["user_errors"]
            stats.failed_events = error_stats["failed_events"]
            
            # Top列表
            stats.top_users = self.get_top_users(cursor, table_name, time_cond, params)
            stats.top_ips = self.get_top_ips(cursor, table_name, time_cond, params)
            stats.top_failed_users = self.get_top_failed_users(cursor, table_name, time_cond, params)
            stats.top_failed_ips = self.get_top_failed_ips(cursor, table_name, time_cond, params)
            
            # 分布数据
            stats.event_type_distribution = self.get_event_distribution(cursor, table_name, time_cond, params)
            stats.hourly_timeline = self.get_hourly_timeline(cursor, table_name, time_cond, params)
            stats.terminal_distribution = self.get_terminal_distribution(cursor, table_name, time_cond, params)
            stats.exe_distribution = self.get_exe_distribution(cursor, table_name, time_cond, params)
            
            # 新增分布统计
            stats.op_distribution = self.get_op_distribution(cursor, table_name, time_cond, params)
            stats.subj_distribution = self.get_subj_distribution(cursor, table_name, time_cond, params)
            stats.grantors_distribution = self.get_grantors_distribution(cursor, table_name, time_cond, params)
            stats.crypto_kind_distribution = self.get_crypto_kind_distribution(cursor, table_name, time_cond, params)
            stats.crypto_direction_distribution = self.get_crypto_direction_distribution(cursor, table_name, time_cond, params)
            
            conn.close()
            
            return {
                "success": True,
                "statistics": stats.to_dict()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_filtered_audit_events(
        self,
        host_id: str,
        event_category: str = None,
        event_type: str = None,
        user: str = None,
        source_ip: str = None,
        result: str = None,
        time_range: str = 'all',
        page: int = 1,
        page_size: int = 50
    ) -> Dict[str, Any]:
        """
        获取过滤后的审计事件列表
        
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
        table_name = self._get_table_name(host_id)
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Check table是否存在
            if not self._table_exists(cursor, table_name):
                conn.close()
                return {
                    "success": False,
                    "error": f"审计日志表不存在: {table_name}"
                }
            
            # 构建WHERE条件
            where_clauses = []
            params = []
            
            # 时间范围
            time_cond, time_params = self._get_time_condition(time_range)
            if time_cond:
                where_clauses.append(time_cond)
                params.extend(time_params)
            
            # 事件分类筛选
            if event_category and event_category in self.EVENT_CATEGORIES:
                types = self.EVENT_CATEGORIES[event_category]
                placeholders = ','.join(['?' for _ in types])
                where_clauses.append(f"audit_type IN ({placeholders})")
                params.extend(types)
            
            # 事件类型筛选
            if event_type:
                where_clauses.append("audit_type = ?")
                params.append(event_type)
            
            # 用户筛选
            if user:
                where_clauses.append("user LIKE ?")
                params.append(f"%{user}%")
            
            # 来源IP筛选
            if source_ip:
                where_clauses.append("source_ip LIKE ?")
                params.append(f"%{source_ip}%")
            
            # 结果筛选
            if result:
                where_clauses.append("result = ?")
                params.append(result)
            
            where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
            
            # 获取总数
            cursor.execute(f"SELECT COUNT(*) FROM {table_name} WHERE {where_sql}", params)
            total = cursor.fetchone()[0]
            
            # 分页查询
            offset = (page - 1) * page_size
            cursor.execute(f"""
                SELECT * FROM {table_name}
                WHERE {where_sql}
                ORDER BY timestamp_unix DESC
                LIMIT ? OFFSET ?
            """, params + [page_size, offset])
            
            events = []
            for row in cursor.fetchall():
                events.append(dict(row))
            
            conn.close()
            
            # 计算分页信息
            total_pages = (total + page_size - 1) // page_size
            
            return {
                "success": True,
                "events": events,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": total,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1
                },
                "filters": {
                    "event_category": event_category,
                    "event_type": event_type,
                    "user": user,
                    "source_ip": source_ip,
                    "result": result,
                    "time_range": time_range
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_audit_event_detail(self, host_id: str, event_id: int) -> Dict[str, Any]:
        """
        获取审计事件详情
        
        返回完整的事件详情，包括:
        - 所有外层字段（pid, uid, auid, ses, subj等）
        - 所有msg内部字段（op, acct, exe, hostname, addr, terminal, res等）
        - 计算字段（user_display, exe_short, is_success, is_remote）
        - 原始日志行内容
        - 额外扩展数据
        
        Args:
            host_id: 主机ID
            event_id: 事件ID
            
        Returns:
            {
                "success": True,
                "event": {...},
                "field_groups": {
                    "basic": [...],      # 基础字段
                    "outer": [...],      # 外层字段
                    "msg_inner": [...],  # msg内部字段
                    "computed": [...],   # 计算字段
                    "crypto": [...],     # 加密相关字段
                    "service": [...],    # 服务相关字段
                    "extra": [...]       # 扩展字段
                }
            }
            
        Requirements: 4.2, 4.4
        """
        import json
        
        table_name = self._get_table_name(host_id)
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Check table是否存在
            if not self._table_exists(cursor, table_name):
                conn.close()
                return {
                    "success": False,
                    "error": f"审计日志表不存在: {table_name}"
                }
            
            cursor.execute(f"SELECT * FROM {table_name} WHERE id = ?", [event_id])
            row = cursor.fetchone()
            
            conn.close()
            
            if not row:
                return {
                    "success": False,
                    "error": f"事件不存在: {event_id}"
                }
            
            # 转换为字典
            event = dict(row)
            
            # 解析extra_json字段
            extra_data = {}
            if event.get('extra_json'):
                try:
                    extra_data = json.loads(event['extra_json'])
                except (json.JSONDecodeError, TypeError):
                    pass
            
            # 合并extra数据到event
            event['extra'] = extra_data
            
            # 生成计算字段（如果数据库中没有存储）
            event = self._enrich_event_detail(event)
            
            # 定义字段分组（用于前端展示）
            field_groups = self._get_field_groups(event)
            
            return {
                "success": True,
                "event": event,
                "field_groups": field_groups
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _enrich_event_detail(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        丰富事件详情，添加计算字段
        
        Args:
            event: 原始事件数据
            
        Returns:
            丰富后的事件数据
        """
        import os
        
        # 生成user_display（如果不存在）
        if not event.get('user_display'):
            acct = event.get('user', '') or event.get('acct', '')
            if acct and acct != '?':
                event['user_display'] = acct
            elif event.get('uid') is not None and event.get('uid') != 4294967295:
                event['user_display'] = str(event['uid'])
            elif event.get('auid') is not None and event.get('auid') != 4294967295:
                event['user_display'] = str(event['auid'])
            else:
                event['user_display'] = ''
        
        # 生成exe_short（如果不存在）
        if not event.get('exe_short'):
            exe = event.get('exe', '')
            if exe:
                event['exe_short'] = os.path.basename(exe.strip('"'))
            else:
                event['exe_short'] = ''
        
        # 生成is_success（如果不存在）
        if 'is_success' not in event:
            result = event.get('result', '')
            event['is_success'] = (result == 'success')
        
        # 生成is_remote（如果不存在）
        if 'is_remote' not in event:
            addr = event.get('source_ip', '')
            event['is_remote'] = bool(addr and addr != '?')
        
        return event
    
    def _get_field_groups(self, event: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        获取字段分组，用于前端展示
        
        Args:
            event: 事件数据
            
        Returns:
            字段分组字典
        """
        # Base fields
        basic_fields = [
            {'key': 'id', 'label': 'ID', 'value': event.get('id')},
            {'key': 'timestamp_str', 'label': '时间', 'value': event.get('timestamp_str')},
            {'key': 'audit_type', 'label': '事件类型', 'value': event.get('audit_type')},
            {'key': 'event_name', 'label': '事件名称', 'value': event.get('event_name')},
            {'key': 'event_category', 'label': '事件分类', 'value': event.get('event_category')},
            {'key': 'audit_serial', 'label': '序列号', 'value': event.get('audit_serial')},
            {'key': 'result', 'label': '结果', 'value': event.get('result')},
            {'key': 'level', 'label': '级别', 'value': event.get('level')},
        ]
        
        # 外层字段（审计日志行中msg外部的字段）
        outer_fields = [
            {'key': 'pid', 'label': '进程ID', 'value': event.get('pid')},
            {'key': 'uid', 'label': '用户ID', 'value': event.get('uid')},
            {'key': 'auid', 'label': '审计用户ID', 'value': event.get('auid')},
            {'key': 'session_id', 'label': '会话ID', 'value': event.get('session_id')},
            {'key': 'subj', 'label': 'SELinux主体', 'value': event.get('subj')},
        ]
        
        # msg内部字段
        msg_inner_fields = [
            {'key': 'operation', 'label': '操作类型', 'value': event.get('operation')},
            {'key': 'user', 'label': '账户名', 'value': event.get('user')},
            {'key': 'exe', 'label': '执行程序', 'value': event.get('exe')},
            {'key': 'hostname', 'label': '主机名', 'value': event.get('hostname')},
            {'key': 'source_ip', 'label': '来源IP', 'value': event.get('source_ip')},
            {'key': 'terminal', 'label': '终端', 'value': event.get('terminal')},
            {'key': 'grantors', 'label': 'PAM授权模块', 'value': event.get('grantors')},
        ]
        
        # 计算字段
        computed_fields = [
            {'key': 'user_display', 'label': '用户显示名', 'value': event.get('user_display')},
            {'key': 'exe_short', 'label': '程序短名', 'value': event.get('exe_short')},
            {'key': 'is_success', 'label': '是否成功', 'value': event.get('is_success')},
            {'key': 'is_remote', 'label': '是否远程', 'value': event.get('is_remote')},
        ]
        
        # 加密相关字段（CRYPTO_KEY_USER等）
        crypto_fields = []
        crypto_keys = ['crypto_fp', 'crypto_kind', 'crypto_direction', 'crypto_spid', 
                       'crypto_suid', 'crypto_laddr', 'crypto_lport', 'crypto_rport',
                       'crypto_cipher', 'crypto_ksize']
        crypto_labels = {
            'crypto_fp': '密钥指纹',
            'crypto_kind': '密钥类型',
            'crypto_direction': '方向',
            'crypto_spid': '子进程ID',
            'crypto_suid': '子进程UID',
            'crypto_laddr': '本地地址',
            'crypto_lport': '本地端口',
            'crypto_rport': '远程端口',
            'crypto_cipher': '加密算法',
            'crypto_ksize': '密钥大小',
        }
        for key in crypto_keys:
            value = event.get(key)
            if value is not None and value != '':
                crypto_fields.append({
                    'key': key,
                    'label': crypto_labels.get(key, key),
                    'value': value
                })
        
        # 服务相关字段（SERVICE_*等）
        service_fields = []
        service_keys = ['service_unit', 'service_comm']
        service_labels = {
            'service_unit': 'systemd单元',
            'service_comm': '命令名',
        }
        for key in service_keys:
            value = event.get(key)
            if value is not None and value != '':
                service_fields.append({
                    'key': key,
                    'label': service_labels.get(key, key),
                    'value': value
                })
        
        # Extended fields（extra中的数据）
        extra_fields = []
        extra_data = event.get('extra', {})
        if isinstance(extra_data, dict):
            for key, value in extra_data.items():
                if value is not None and value != '':
                    extra_fields.append({
                        'key': key,
                        'label': key,
                        'value': value
                    })
        
        # 原始日志行
        raw_fields = [
            {'key': 'raw_line', 'label': '原始日志', 'value': event.get('raw_line')},
            {'key': 'message', 'label': '消息', 'value': event.get('message')},
        ]
        
        # 过滤掉空值字段
        def filter_empty(fields):
            return [f for f in fields if f['value'] is not None and f['value'] != '']
        
        return {
            'basic': filter_empty(basic_fields),
            'outer': filter_empty(outer_fields),
            'msg_inner': filter_empty(msg_inner_fields),
            'computed': filter_empty(computed_fields),
            'crypto': crypto_fields,
            'service': service_fields,
            'extra': extra_fields,
            'raw': raw_fields,
        }
    
    def get_available_filters(self, host_id: str) -> Dict[str, Any]:
        """
        获取可用的筛选选项
        
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
        table_name = self._get_table_name(host_id)
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            # Check table是否存在
            if not self._table_exists(cursor, table_name):
                conn.close()
                return {
                    "success": False,
                    "error": f"审计日志表不存在: {table_name}"
                }
            
            # Get events类型列表
            cursor.execute(f"""
                SELECT DISTINCT audit_type FROM {table_name}
                WHERE audit_type IS NOT NULL
                ORDER BY audit_type
            """)
            event_types = [row[0] for row in cursor.fetchall()]
            
            # 获取用户列表
            cursor.execute(f"""
                SELECT DISTINCT user FROM {table_name}
                WHERE user IS NOT NULL AND user != ''
                ORDER BY user
                LIMIT 100
            """)
            users = [row[0] for row in cursor.fetchall()]
            
            # 获取来源IP列表
            cursor.execute(f"""
                SELECT DISTINCT source_ip FROM {table_name}
                WHERE source_ip IS NOT NULL AND source_ip != ''
                ORDER BY source_ip
                LIMIT 100
            """)
            source_ips = [row[0] for row in cursor.fetchall()]
            
            conn.close()
            
            # 事件分类
            event_categories = [
                {"key": k, "name": self.CATEGORY_NAMES.get(k, k)}
                for k in self.EVENT_CATEGORIES.keys()
            ]
            
            return {
                "success": True,
                "filters": {
                    "event_types": event_types,
                    "event_categories": event_categories,
                    "users": users,
                    "source_ips": source_ips
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
