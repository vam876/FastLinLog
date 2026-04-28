#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SQLite缓存管理器
每种日志类型一个表，支持多主机
"""

import os
import sys
import sqlite3
import json
import time
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Generator
from dataclasses import dataclass, field

from .log_event import LogEvent


@dataclass
class ImportStatistics:
    """导入统计信息"""
    file_path: str
    log_type: str
    host_id: str
    table_name: str
    
    # 统计数据
    total_lines: int = 0              # 文件总行数
    parsed_success: int = 0           # 解析成功数
    parsed_failed: int = 0            # 解析失败数
    skipped: int = 0                  # 跳过的行数
    inserted: int = 0                 # 实际插入数
    
    # 时间信息
    start_time: float = 0
    end_time: float = 0
    duration: float = 0
    
    # Error信息
    errors: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "file_path": self.file_path,
            "log_type": self.log_type,
            "host_id": self.host_id,
            "table_name": self.table_name,
            "total_lines": self.total_lines,
            "parsed_success": self.parsed_success,
            "parsed_failed": self.parsed_failed,
            "skipped": self.skipped,
            "inserted": self.inserted,
            "duration": self.duration,
            "errors": self.errors[:10]  # 只返回前10个错误
        }


class LinuxLogCacheManager:
    """Linux日志SQLite缓存管理器"""
    
    def __init__(self, cache_dir: str = "cache/linux"):
        # Get base directory
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        self.cache_dir = os.path.join(base_dir, cache_dir)
        os.makedirs(self.cache_dir, exist_ok=True)
        
        self.db_path = os.path.join(self.cache_dir, "linux_logs.db")
        self._init_database()
        
        print(f"[LinuxCache] 缓存目录: {self.cache_dir}")
    
    def _init_database(self):
        """初始化数据库结构"""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        cursor = conn.cursor()
        
        # Optimization settings
        conn.execute('PRAGMA journal_mode = WAL')
        conn.execute('PRAGMA synchronous = NORMAL')
        conn.execute('PRAGMA cache_size = -64000')
        
        # Metadata table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        
        # 文件缓存状态表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_cache_status (
                file_path TEXT PRIMARY KEY,
                file_hash TEXT,
                file_mtime REAL,
                file_size INTEGER,
                log_type TEXT,
                host_id TEXT,
                event_count INTEGER DEFAULT 0,
                cached_at TEXT,
                table_name TEXT
            )
        ''')
        
        # 导入历史表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS import_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                log_type TEXT NOT NULL,
                host_id TEXT NOT NULL,
                table_name TEXT NOT NULL,
                
                -- 统计数据
                total_lines INTEGER DEFAULT 0,
                parsed_success INTEGER DEFAULT 0,
                parsed_failed INTEGER DEFAULT 0,
                skipped INTEGER DEFAULT 0,
                inserted INTEGER DEFAULT 0,
                
                -- 时间信息
                import_start TEXT,
                import_end TEXT,
                duration_seconds REAL,
                
                -- 状态
                status TEXT,
                error_summary TEXT,
                
                -- 索引
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create index
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_import_history_file 
            ON import_history(file_path)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_import_history_table 
            ON import_history(table_name)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_import_history_time 
            ON import_history(created_at)
        ''')
        
        # 为file_cache_status表添加统计字段（向后兼容）
        # Check column是否存在，如果不存在则添加
        cursor.execute("PRAGMA table_info(file_cache_status)")
        existing_columns = {row[1] for row in cursor.fetchall()}
        
        if 'parsed_lines' not in existing_columns:
            cursor.execute('ALTER TABLE file_cache_status ADD COLUMN parsed_lines INTEGER DEFAULT 0')
        
        if 'failed_lines' not in existing_columns:
            cursor.execute('ALTER TABLE file_cache_status ADD COLUMN failed_lines INTEGER DEFAULT 0')
        
        if 'skipped_lines' not in existing_columns:
            cursor.execute('ALTER TABLE file_cache_status ADD COLUMN skipped_lines INTEGER DEFAULT 0')
        
        if 'last_import_id' not in existing_columns:
            cursor.execute('ALTER TABLE file_cache_status ADD COLUMN last_import_id INTEGER')
        
        conn.commit()
        conn.close()
    
    def _get_table_name(self, log_type: str, host_id: str = None) -> str:
        """
        生成表名
        
        格式: events_{log_type}_{host_hash}
        例如: events_audit_a1b2c3d4
        """
        if host_id:
            host_hash = hashlib.md5(host_id.encode()).hexdigest()[:8]
            return f"events_{log_type}_{host_hash}"
        return f"events_{log_type}"
    
    def _create_log_table(self, conn: sqlite3.Connection, table_name: str, log_type: str):
        """
        创建日志表
        根据日志类型创建不同的表结构
        """
        cursor = conn.cursor()
        
        # 基础字段 (所有日志通用)
        base_fields = '''
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT,
            record_id INTEGER,
            
            -- 统一时间字段
            timestamp_unix INTEGER,
            timestamp_usec INTEGER,
            timestamp_str TEXT,
            
            -- 来源
            hostname TEXT,
            source_file TEXT,
            
            -- 进程
            process TEXT,
            pid INTEGER,
            
            -- 用户
            user TEXT,
            uid INTEGER,
            target_user TEXT,
            
            -- 网络
            source_ip TEXT,
            source_port INTEGER,
            
            -- 事件
            event_type TEXT,
            event_name TEXT,
            event_category TEXT,
            level TEXT,
            result TEXT,
            
            -- 消息
            message TEXT,
            raw_line TEXT
        '''
        
        # 根据日志类型添加特定字段
        extra_fields = ""
        
        if log_type == "audit":
            extra_fields = '''
                ,audit_type TEXT,
                audit_serial INTEGER,
                auid INTEGER,
                session_id INTEGER,
                exe TEXT,
                terminal TEXT,
                operation TEXT,
                -- 新增msg内部字段
                op TEXT,
                acct TEXT,
                res TEXT,
                grantors TEXT,
                subj TEXT,
                -- 计算字段
                user_display TEXT,
                exe_short TEXT,
                is_success INTEGER,
                is_remote INTEGER,
                -- CRYPTO字段
                crypto_fp TEXT,
                crypto_kind TEXT,
                crypto_direction TEXT,
                crypto_spid INTEGER,
                crypto_suid INTEGER,
                crypto_laddr TEXT,
                crypto_lport INTEGER,
                crypto_rport INTEGER,
                crypto_cipher TEXT,
                crypto_ksize INTEGER,
                -- SERVICE字段
                service_unit TEXT,
                service_comm TEXT
            '''
        elif log_type in ("btmp", "wtmp"):
            extra_fields = '''
                ,ut_type INTEGER,
                ut_type_name TEXT,
                line TEXT
            '''
        elif log_type == "lastlog":
            extra_fields = '''
                ,line TEXT
            '''
        elif log_type in ("secure", "auth"):
            extra_fields = '''
                ,session_id INTEGER,
                auth_method TEXT
            '''
        
        # 扩展JSON字段 (存储其他数据)
        extra_fields += '''
            ,extra_json TEXT
        '''
        
        # 使用 IF NOT EXISTS 创建表，避免竞争条件
        try:
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS {table_name} (
                    {base_fields}
                    {extra_fields}
                )
            ''')
            
            # 创建索引 (使用 IF NOT EXISTS)
            cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_{table_name}_time ON {table_name}(timestamp_unix)')
            cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_{table_name}_type ON {table_name}(event_type)')
            cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_{table_name}_user ON {table_name}(user)')
            cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_{table_name}_ip ON {table_name}(source_ip)')
            cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_{table_name}_level ON {table_name}(level)')
            cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_{table_name}_file ON {table_name}(file_path)')
            
            # 审计日志专用索引
            if log_type == "audit":
                cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_{table_name}_audit_type ON {table_name}(audit_type)')
                cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_{table_name}_user_display ON {table_name}(user_display)')
                cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_{table_name}_res ON {table_name}(res)')
                cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_{table_name}_category ON {table_name}(event_category)')
            
            conn.commit()
        except sqlite3.OperationalError as e:
            # 忽略"table already exists"错误
            if "already exists" not in str(e):
                raise
    
    def is_cache_valid(self, file_path: str) -> bool:
        """检查文件缓存是否有效"""
        if not os.path.exists(file_path):
            return False
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT file_mtime, file_size FROM file_cache_status 
                WHERE file_path = ?
            ''', (file_path,))
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return False
            
            cached_mtime, cached_size = row
            current_mtime = os.path.getmtime(file_path)
            current_size = os.path.getsize(file_path)
            
            # 允许60秒误差
            return abs(current_mtime - cached_mtime) < 60 and current_size == cached_size
            
        except Exception as e:
            print(f"[LinuxCache] 检查缓存失败: {e}")
            return False
    
    def cache_events(self, file_path: str, log_type: str, host_id: str,
                     events: Generator[LogEvent, None, None],
                     show_progress: bool = True) -> dict:
        """
        缓存事件到SQLite
        
        Args:
            file_path: 源文件路径
            log_type: 日志类型
            host_id: 主机ID
            events: 事件生成器
            show_progress: 显示进度
            
        Returns:
            {"success": True, "event_count": 1234, "table_name": "events_audit_xxx"}
        """
        result, _ = self.cache_events_with_stats(file_path, log_type, host_id, events, show_progress)
        return result
    
    def cache_events_with_stats(self, file_path: str, log_type: str, host_id: str,
                                events: Generator[LogEvent, None, None],
                                show_progress: bool = True) -> tuple:
        """
        缓存事件到SQLite并返回详细统计
        
        Args:
            file_path: 源文件路径
            log_type: 日志类型
            host_id: 主机ID
            events: 事件生成器
            show_progress: 显示进度
            
        Returns:
            (result_dict, ImportStatistics)
        """
        table_name = self._get_table_name(log_type, host_id)
        
        # 初始化统计对象
        stats = ImportStatistics(
            file_path=file_path,
            log_type=log_type,
            host_id=host_id,
            table_name=table_name,
            start_time=time.time()
        )
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            
            # Create table
            self._create_log_table(conn, table_name, log_type)
            
            cursor = conn.cursor()
            
            # 删除该文件的旧数据
            cursor.execute(f'DELETE FROM {table_name} WHERE file_path = ?', (file_path,))
            
            # Batch insert
            batch_size = 1000
            batch = []
            line_number = 0
            
            for event in events:
                line_number += 1
                stats.total_lines += 1
                
                try:
                    # 检查事件是否有效
                    if event is None:
                        stats.skipped += 1
                        continue
                    
                    # 尝试转换为数据库行
                    row = self._event_to_row(event, file_path, log_type)
                    batch.append(row)
                    stats.parsed_success += 1
                    
                    if len(batch) >= batch_size:
                        inserted = self._insert_batch(cursor, table_name, batch, log_type)
                        stats.inserted += inserted
                        batch = []
                        
                        if show_progress:
                            elapsed = time.time() - stats.start_time
                            speed = stats.total_lines / elapsed if elapsed > 0 else 0
                            print(f"\r  [缓存] {stats.total_lines}行 | 成功:{stats.parsed_success} 失败:{stats.parsed_failed} 跳过:{stats.skipped} | {speed:.0f}行/秒", end='')
                
                except Exception as e:
                    # 记录解析失败
                    stats.parsed_failed += 1
                    if len(stats.errors) < 100:  # 最多记录100个错误
                        stats.errors.append({
                            "line_number": line_number,
                            "reason": str(e),
                            "raw_line": getattr(event, 'raw_line', '')[:200] if event else ''
                        })
            
            # 插入剩余数据
            if batch:
                inserted = self._insert_batch(cursor, table_name, batch, log_type)
                stats.inserted += inserted
            
            # Update statistics时间
            stats.end_time = time.time()
            stats.duration = stats.end_time - stats.start_time
            
            # Update cache状态
            cursor.execute('''
                INSERT OR REPLACE INTO file_cache_status 
                (file_path, file_mtime, file_size, log_type, host_id, event_count, cached_at, table_name,
                 parsed_lines, failed_lines, skipped_lines)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_path,
                os.path.getmtime(file_path),
                os.path.getsize(file_path),
                log_type,
                host_id,
                stats.inserted,
                datetime.now().isoformat(),
                table_name,
                stats.parsed_success,
                stats.parsed_failed,
                stats.skipped
            ))
            
            conn.commit()
            conn.close()
            
            if show_progress:
                print(f"\n  [缓存] 完成: {stats.inserted}条插入 | 总行数:{stats.total_lines} 成功:{stats.parsed_success} 失败:{stats.parsed_failed} 跳过:{stats.skipped} | 耗时{stats.duration:.1f}秒")
            
            result = {
                "success": True,
                "event_count": stats.inserted,
                "table_name": table_name,
                "statistics": stats.to_dict()
            }
            
            return result, stats
            
        except Exception as e:
            stats.end_time = time.time()
            stats.duration = stats.end_time - stats.start_time
            print(f"\n[LinuxCache] 缓存失败: {e}")
            return {"success": False, "error": str(e)}, stats
    
    def cache_events_with_progress(self, file_path: str, log_type: str, host_id: str,
                                   events: Generator[LogEvent, None, None],
                                   progress_callback=None,
                                   show_progress: bool = False) -> dict:
        """
        缓存事件到SQLite，支持进度回调
        
        Args:
            file_path: 源文件路径
            log_type: 日志类型
            host_id: 主机ID
            events: 事件生成器
            progress_callback: 进度回调函数 (current_lines, total_lines)
            show_progress: 显示进度
            
        Returns:
            {"success": True, "event_count": 1234, "table_name": "events_audit_xxx"}
        """
        table_name = self._get_table_name(log_type, host_id)
        
        # 初始化统计
        start_time = time.time()
        total_lines = 0
        parsed_success = 0
        parsed_failed = 0
        skipped = 0
        inserted = 0
        
        # 进度更新间隔（每处理多少行更新一次）
        progress_interval =500  # 每100行更新一次进度
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            
            # Create table
            self._create_log_table(conn, table_name, log_type)
            
            cursor = conn.cursor()
            
            # 删除该文件的旧数据
            cursor.execute(f'DELETE FROM {table_name} WHERE file_path = ?', (file_path,))
            
            # Batch insert
            batch_size = 1000  # 减小批次大小以更频繁更新进度
            batch = []
            
            for event in events:
                total_lines += 1
                
                try:
                    if event is None:
                        skipped += 1
                        continue
                    
                    row = self._event_to_row(event, file_path, log_type)
                    batch.append(row)
                    parsed_success += 1
                    
                    if len(batch) >= batch_size:
                        batch_inserted = self._insert_batch(cursor, table_name, batch, log_type)
                        inserted += batch_inserted
                        batch = []
                        
                        # 调用进度回调
                        if progress_callback and total_lines % progress_interval == 0:
                            progress_callback(total_lines, 0)
                
                except Exception as e:
                    parsed_failed += 1
                    # 每处理一定行数也更新进度
                    if progress_callback and total_lines % progress_interval == 0:
                        progress_callback(total_lines, 0)
            
            # 插入剩余数据
            if batch:
                batch_inserted = self._insert_batch(cursor, table_name, batch, log_type)
                inserted += batch_inserted
            
            # 最终进度回调
            if progress_callback:
                progress_callback(total_lines, total_lines)
            
            # Update cache状态
            cursor.execute('''
                INSERT OR REPLACE INTO file_cache_status 
                (file_path, file_mtime, file_size, log_type, host_id, event_count, cached_at, table_name,
                 parsed_lines, failed_lines, skipped_lines)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_path,
                os.path.getmtime(file_path),
                os.path.getsize(file_path),
                log_type,
                host_id,
                inserted,
                datetime.now().isoformat(),
                table_name,
                parsed_success,
                parsed_failed,
                skipped
            ))
            
            conn.commit()
            conn.close()
            
            duration = time.time() - start_time
            if show_progress:
                print(f"\n  [缓存] 完成: {inserted}条插入 | 耗时{duration:.1f}秒")
            
            return {
                "success": True,
                "event_count": inserted,
                "table_name": table_name
            }
            
        except Exception as e:
            print(f"\n[LinuxCache] 缓存失败: {e}")
            return {"success": False, "error": str(e)}
    
    def _event_to_row(self, event: LogEvent, file_path: str, log_type: str) -> tuple:
        """将事件转换为数据库行"""
        # 处理level字段 - 如果是枚举类型则转换为字符串
        level_value = event.level
        if hasattr(level_value, 'value'):
            level_value = level_value.value
        elif not isinstance(level_value, str):
            level_value = str(level_value) if level_value else ''
        
        # 处理result字段 - 如果是枚举类型则转换为字符串
        result_value = event.result
        if hasattr(result_value, 'value'):
            result_value = result_value.value
        elif not isinstance(result_value, str):
            result_value = str(result_value) if result_value else ''
        
        base = (
            file_path,
            event.record_id,
            event.timestamp_unix,
            event.timestamp_usec,
            event.timestamp_str,
            event.hostname,
            event.source_file,
            event.process,
            event.pid,
            event.user,
            event.uid,
            event.target_user,
            event.source_ip,
            event.source_port,
            event.event_type,
            event.event_name,
            event.event_category,
            level_value,
            result_value,
            event.message,
            event.raw_line,
        )
        
        # 根据日志类型添加特定字段
        if log_type == "audit":
            extra = (
                event.audit_type,
                event.audit_serial,
                event.auid,
                event.session_id,
                event.exe,
                event.terminal,
                event.operation,
                # 新增msg内部字段 (op, acct, res, grantors, subj)
                getattr(event, 'audit_op', '') or event.operation,  # op
                getattr(event, 'audit_acct', '') or event.user,     # acct
                result_value if result_value else '',               # res
                getattr(event, 'grantors', ''),                     # grantors
                getattr(event, 'subj', ''),                         # subj
                # 计算字段 (user_display, exe_short, is_success, is_remote)
                getattr(event, 'user_display', ''),
                getattr(event, 'exe_short', ''),
                1 if getattr(event, 'is_success', False) else 0,
                1 if getattr(event, 'is_remote', False) else 0,
                # CRYPTO字段 (10个)
                getattr(event, 'crypto_fp', ''),
                getattr(event, 'crypto_kind', ''),
                getattr(event, 'crypto_direction', ''),
                getattr(event, 'crypto_spid', None),
                getattr(event, 'crypto_suid', None),
                getattr(event, 'crypto_laddr', ''),
                getattr(event, 'crypto_lport', None),
                getattr(event, 'crypto_rport', None),
                getattr(event, 'crypto_cipher', ''),
                getattr(event, 'crypto_ksize', None),
                # SERVICE字段 (2个)
                getattr(event, 'service_unit', ''),
                getattr(event, 'service_comm', ''),
            )
            # 总计: 7 + 5 + 4 + 10 + 2 = 28个额外字段
        elif log_type in ("btmp", "wtmp"):
            extra = (
                event.ut_type,
                event.ut_type_name,
                event.line,
            )
        elif log_type == "lastlog":
            extra = (
                event.line,
            )
        elif log_type in ("secure", "auth"):
            extra = (
                event.session_id,
                event.extra.get('auth_method', ''),
            )
        else:
            extra = ()
        
        # JSON扩展数据
        extra_json = json.dumps(event.extra, ensure_ascii=False) if event.extra else None
        
        return base + extra + (extra_json,)
    
    def _insert_batch(self, cursor, table_name: str, batch: List[tuple], log_type: str) -> int:
        """批量插入，返回插入的行数"""
        # 根据日志类型确定字段数
        base_fields = 21  # 基础字段数
        
        if log_type == "audit":
            extra_count = 28  # 7 original + 5 msg + 4 computed + 10 crypto + 2 service
        elif log_type in ("btmp", "wtmp"):
            extra_count = 3
        elif log_type == "lastlog":
            extra_count = 1
        elif log_type in ("secure", "auth"):
            extra_count = 2
        else:
            extra_count = 0
        
        total_fields = base_fields + extra_count + 1  # +1 for extra_json
        placeholders = ','.join(['?'] * total_fields)
        
        cursor.executemany(f'''
            INSERT INTO {table_name} VALUES (NULL, {placeholders})
        ''', batch)
        
        return len(batch)
    
    def save_import_history(self, stats: ImportStatistics) -> Optional[int]:
        """
        保存导入历史记录
        
        Args:
            stats: ImportStatistics对象
            
        Returns:
            导入历史记录的ID，失败返回None
        """
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            # 确定状态
            if stats.parsed_failed > 0 or stats.skipped > 0:
                if stats.inserted > 0:
                    status = 'partial'
                else:
                    status = 'failed'
            else:
                status = 'success'
            
            # 生成错误摘要
            error_summary = None
            if stats.errors:
                error_summary = f"{len(stats.errors)} errors recorded"
                if len(stats.errors) > 0:
                    error_summary += f": {stats.errors[0]['reason']}"
            
            # 插入历史记录
            cursor.execute('''
                INSERT INTO import_history 
                (file_path, log_type, host_id, table_name,
                 total_lines, parsed_success, parsed_failed, skipped, inserted,
                 import_start, import_end, duration_seconds, status, error_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                stats.file_path,
                stats.log_type,
                stats.host_id,
                stats.table_name,
                stats.total_lines,
                stats.parsed_success,
                stats.parsed_failed,
                stats.skipped,
                stats.inserted,
                datetime.fromtimestamp(stats.start_time).isoformat(),
                datetime.fromtimestamp(stats.end_time).isoformat(),
                stats.duration,
                status,
                error_summary
            ))
            
            import_id = cursor.lastrowid
            
            # 更新file_cache_status的last_import_id
            cursor.execute('''
                UPDATE file_cache_status 
                SET last_import_id = ?
                WHERE file_path = ?
            ''', (import_id, stats.file_path))
            
            conn.commit()
            conn.close()
            
            return import_id
            
        except Exception as e:
            print(f"[LinuxCache] 保存导入历史失败: {e}")
            return None
    
    def get_import_history(self, file_path: str = None, 
                          time_range_hours: int = None,
                          limit: int = 100) -> List[Dict[str, Any]]:
        """
        获取导入历史记录
        
        Args:
            file_path: 文件路径（可选，用于筛选特定文件）
            time_range_hours: 时间范围（小时）
            limit: 返回记录数限制
            
        Returns:
            历史记录列表
        """
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Build query条件
            where_clauses = []
            params = []
            
            if file_path:
                where_clauses.append("file_path = ?")
                params.append(file_path)
            
            if time_range_hours:
                cutoff_time = datetime.now() - timedelta(hours=time_range_hours)
                where_clauses.append("created_at >= ?")
                params.append(cutoff_time.isoformat())
            
            where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
            
            # 查询历史记录
            cursor.execute(f'''
                SELECT * FROM import_history
                WHERE {where_sql}
                ORDER BY created_at DESC, id DESC
                LIMIT ?
            ''', params + [limit])
            
            history = []
            for row in cursor.fetchall():
                history.append(dict(row))
            
            conn.close()
            
            return history
            
        except Exception as e:
            print(f"[LinuxCache] 获取导入历史失败: {e}")
            return []
    
    def verify_import_consistency(self, file_path: str) -> Dict[str, Any]:
        """
        验证导入数据一致性
        
        Args:
            file_path: 文件路径
            
        Returns:
            {
                "consistent": True/False,
                "expected_count": 1234,
                "actual_count": 1234,
                "difference": 0,
                "issues": []
            }
        """
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            # 查询file_cache_status中的记录
            cursor.execute('''
                SELECT event_count, table_name, parsed_lines, failed_lines, skipped_lines
                FROM file_cache_status
                WHERE file_path = ?
            ''', (file_path,))
            
            row = cursor.fetchone()
            if not row:
                conn.close()
                return {
                    "consistent": False,
                    "expected_count": 0,
                    "actual_count": 0,
                    "difference": 0,
                    "issues": ["文件未在缓存中"]
                }
            
            expected_count, table_name, parsed_lines, failed_lines, skipped_lines = row
            
            # 查询数据库中的实际记录数
            cursor.execute(f'''
                SELECT COUNT(*) FROM {table_name}
                WHERE file_path = ?
            ''', (file_path,))
            
            actual_count = cursor.fetchone()[0]
            
            conn.close()
            
            # 计算差异
            difference = actual_count - expected_count
            issues = []
            
            if difference != 0:
                issues.append(f"事件数量不一致: 预期{expected_count}, 实际{actual_count}, 差异{difference}")
            
            # 检查统计一致性
            if parsed_lines is not None and failed_lines is not None and skipped_lines is not None:
                total_processed = parsed_lines + failed_lines + skipped_lines
                if parsed_lines != expected_count:
                    issues.append(f"解析成功数({parsed_lines})与事件数({expected_count})不一致")
            
            return {
                "consistent": len(issues) == 0,
                "expected_count": expected_count,
                "actual_count": actual_count,
                "difference": difference,
                "issues": issues,
                "file_path": file_path,
                "table_name": table_name
            }
            
        except Exception as e:
            return {
                "consistent": False,
                "expected_count": 0,
                "actual_count": 0,
                "difference": 0,
                "issues": [f"验证失败: {str(e)}"]
            }
    
    def get_file_aggregation_info(self, log_type: str, host_id: str) -> Dict[str, Any]:
        """
        获取文件汇聚信息
        
        Args:
            log_type: 日志类型
            host_id: 主机ID
            
        Returns:
            {
                "table_name": "events_wtmp_xxx",
                "file_count": 5,
                "files": [
                    {
                        "file_path": "...",
                        "file_name": "wtmp",
                        "event_count": 1234,
                        "cached_at": "2024-01-01 12:00:00"
                    },
                    ...
                ],
                "total_events": 6789
            }
        """
        table_name = self._get_table_name(log_type, host_id)
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # 查询该表对应的所有文件
            cursor.execute('''
                SELECT file_path, event_count, cached_at
                FROM file_cache_status
                WHERE table_name = ? AND host_id = ?
                ORDER BY file_path
            ''', (table_name, host_id))
            
            files = []
            total_events = 0
            
            for row in cursor.fetchall():
                file_path = row['file_path']
                event_count = row['event_count'] or 0
                cached_at = row['cached_at']
                
                # 提取文件名
                file_name = os.path.basename(file_path)
                
                files.append({
                    "file_path": file_path,
                    "file_name": file_name,
                    "event_count": event_count,
                    "cached_at": cached_at
                })
                
                total_events += event_count
            
            conn.close()
            
            return {
                "table_name": table_name,
                "log_type": log_type,
                "file_count": len(files),
                "files": files,
                "total_events": total_events
            }
            
        except Exception as e:
            print(f"[LinuxCache] 获取汇聚信息失败: {e}")
            return {
                "table_name": table_name,
                "log_type": log_type,
                "file_count": 0,
                "files": [],
                "total_events": 0
            }
    
    def load_events(self, file_path: str = None, log_type: str = None, host_id: str = None,
                    page: int = 1, page_size: int = 100,
                    sort_field: str = "timestamp_unix", sort_direction: str = "desc",
                    filters: Dict[str, Any] = None) -> dict:
        """
        从缓存加载事件
        
        Args:
            file_path: 文件路径 (可选，用于筛选特定文件)
            log_type: 日志类型
            host_id: 主机ID
            page: 页码
            page_size: 每页大小
            sort_field: 排序字段
            sort_direction: 排序方向
            filters: 筛选条件
            
        Returns:
            {"success": True, "events": [...], "pagination": {...}}
        """
        table_name = self._get_table_name(log_type, host_id)
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Check table是否存在
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
            if not cursor.fetchone():
                conn.close()
                return {"success": False, "error": f"表不存在: {table_name}"}
            
            # 构建WHERE条件
            where_clauses = []
            params = []
            
            if file_path:
                where_clauses.append("file_path = ?")
                params.append(file_path)
            
            if filters:
                for field, value in filters.items():
                    if value:
                        where_clauses.append(f"{field} LIKE ?")
                        params.append(f"%{value}%")
            
            where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
            
            # 获取总数
            cursor.execute(f"SELECT COUNT(*) FROM {table_name} WHERE {where_sql}", params)
            total = cursor.fetchone()[0]
            
            # 排序
            direction = "DESC" if sort_direction.lower() == "desc" else "ASC"
            order_sql = f"ORDER BY {sort_field} {direction}"
            
            # 分页
            offset = (page - 1) * page_size
            
            # 查询
            cursor.execute(f'''
                SELECT * FROM {table_name} 
                WHERE {where_sql} 
                {order_sql}
                LIMIT ? OFFSET ?
            ''', params + [page_size, offset])
            
            events = []
            for row in cursor.fetchall():
                event = self._row_to_dict(row, log_type)
                events.append(event)
            
            conn.close()
            
            total_pages = (total + page_size - 1) // page_size if total > 0 else 1
            
            return {
                "success": True,
                "events": events,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_count": total,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1
                },
                "from_cache": True
            }
            
        except Exception as e:
            print(f"[LinuxCache] 加载失败: {e}")
            return {"success": False, "error": str(e)}
    
    def _row_to_dict(self, row: sqlite3.Row, log_type: str) -> dict:
        """将数据库行转换为字典"""
        result = dict(row)
        
        # 解析extra_json
        if result.get('extra_json'):
            try:
                result['extra'] = json.loads(result['extra_json'])
            except:
                result['extra'] = {}
            del result['extra_json']
        else:
            result['extra'] = {}
        
        # 删除内部ID
        if 'id' in result:
            del result['id']
        
        return result
    
    def get_statistics(self, log_type: str, host_id: str = None,
                       time_range_hours: int = None) -> dict:
        """
        获取统计数据
        
        Args:
            log_type: 日志类型
            host_id: 主机ID
            time_range_hours: 时间范围(小时)
            
        Returns:
            统计数据
        """
        table_name = self._get_table_name(log_type, host_id)
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            # Check table是否存在
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
            if not cursor.fetchone():
                conn.close()
                return {"success": False, "error": "无数据"}
            
            # 时间条件
            time_condition = ""
            params = []
            if time_range_hours:
                min_time = int(time.time()) - (time_range_hours * 3600)
                time_condition = "WHERE timestamp_unix >= ?"
                params = [min_time]
            
            stats = {
                "total_events": 0,
                "by_event_type": {},
                "by_user": {},
                "by_source_ip": {},
                "by_result": {},
                "by_level": {},
                "time_range": {"start": None, "end": None}
            }
            
            # 总数
            cursor.execute(f"SELECT COUNT(*) FROM {table_name} {time_condition}", params)
            stats["total_events"] = cursor.fetchone()[0]
            
            # 按事件类型
            cursor.execute(f'''
                SELECT event_type, COUNT(*) as cnt FROM {table_name} 
                {time_condition}
                GROUP BY event_type ORDER BY cnt DESC LIMIT 20
            ''', params)
            stats["by_event_type"] = {row[0] or "UNKNOWN": row[1] for row in cursor.fetchall()}
            
            # 按用户
            cursor.execute(f'''
                SELECT user, COUNT(*) as cnt FROM {table_name} 
                {time_condition} {"AND" if time_condition else "WHERE"} user IS NOT NULL AND user != ''
                GROUP BY user ORDER BY cnt DESC LIMIT 20
            ''', params)
            stats["by_user"] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # 按来源IP
            cursor.execute(f'''
                SELECT source_ip, COUNT(*) as cnt FROM {table_name} 
                {time_condition} {"AND" if time_condition else "WHERE"} source_ip IS NOT NULL AND source_ip != ''
                GROUP BY source_ip ORDER BY cnt DESC LIMIT 20
            ''', params)
            stats["by_source_ip"] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # 按结果
            cursor.execute(f'''
                SELECT result, COUNT(*) as cnt FROM {table_name} 
                {time_condition} {"AND" if time_condition else "WHERE"} result IS NOT NULL AND result != ''
                GROUP BY result
            ''', params)
            stats["by_result"] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # 按级别
            cursor.execute(f'''
                SELECT level, COUNT(*) as cnt FROM {table_name} 
                {time_condition}
                GROUP BY level
            ''', params)
            stats["by_level"] = {row[0] or "INFO": row[1] for row in cursor.fetchall()}
            
            # 时间范围
            cursor.execute(f'''
                SELECT MIN(timestamp_str), MAX(timestamp_str) FROM {table_name}
                {time_condition}
            ''', params)
            row = cursor.fetchone()
            if row:
                stats["time_range"]["start"] = row[0]
                stats["time_range"]["end"] = row[1]
            
            conn.close()
            
            return {"success": True, "statistics": stats}
            
        except Exception as e:
            print(f"[LinuxCache] 统计失败: {e}")
            return {"success": False, "error": str(e)}
    
    def get_file_statistics(self, file_path: str, time_range_hours: int = None) -> dict:
        """
        获取单个文件的统计
        """
        stats = {
            "login_success": 0,
            "login_failed": 0,
            "invalid_user_attempts": 0,
            "sudo_success": 0,
            "sudo_denied": 0,
            "top_failed_ips": [],
            "top_failed_users": [],
            "top_success_users": [],
            "top_sudo_users": [],
            "hourly_timeline": [],
            "event_type_distribution": [],
            "total_events": 0
        }
        
        failed_ips = {}
        failed_users = {}
        success_users = {}
        sudo_users = {}
        event_types = {}
        hourly_data = {}
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            # 查找该文件对应的表
            cursor.execute('SELECT table_name FROM file_cache_status WHERE file_path = ?', (file_path,))
            row = cursor.fetchone()
            if not row:
                conn.close()
                return {"success": True, "statistics": stats, "message": "文件未缓存"}
            
            table_name = row[0]
            min_time = int(time.time()) - (time_range_hours * 3600) if time_range_hours else 0
            
            # 总事件数
            cursor.execute(f'SELECT COUNT(*) FROM {table_name} WHERE file_path = ? AND timestamp_unix >= ?', 
                          (file_path, min_time))
            stats["total_events"] = cursor.fetchone()[0]
            
            # 登录成功
            cursor.execute(f'''
                SELECT COUNT(*) FROM {table_name}
                WHERE file_path = ? AND timestamp_unix >= ? AND event_type LIKE 'SSH_ACCEPTED%'
            ''', (file_path, min_time))
            stats["login_success"] = cursor.fetchone()[0]
            
            # 登录失败
            cursor.execute(f'''
                SELECT COUNT(*) FROM {table_name}
                WHERE file_path = ? AND timestamp_unix >= ? AND event_type LIKE 'SSH_FAILED%'
            ''', (file_path, min_time))
            stats["login_failed"] = cursor.fetchone()[0]
            
            # 无效用户
            cursor.execute(f'''
                SELECT COUNT(*) FROM {table_name}
                WHERE file_path = ? AND timestamp_unix >= ? AND event_type = 'SSH_INVALID_USER'
            ''', (file_path, min_time))
            stats["invalid_user_attempts"] = cursor.fetchone()[0]
            
            # Sudo成功
            cursor.execute(f'''
                SELECT COUNT(*) FROM {table_name}
                WHERE file_path = ? AND timestamp_unix >= ? AND event_type = 'SUDO_COMMAND'
            ''', (file_path, min_time))
            stats["sudo_success"] = cursor.fetchone()[0]
            
            # Sudo拒绝
            cursor.execute(f'''
                SELECT COUNT(*) FROM {table_name}
                WHERE file_path = ? AND timestamp_unix >= ? AND event_type = 'SUDO_NOT_IN_SUDOERS'
            ''', (file_path, min_time))
            stats["sudo_denied"] = cursor.fetchone()[0]
            
            # Top失败IP
            cursor.execute(f'''
                SELECT source_ip, COUNT(*) as cnt FROM {table_name}
                WHERE file_path = ? AND timestamp_unix >= ? 
                  AND result = 'failed' 
                  AND source_ip IS NOT NULL AND source_ip != ''
                GROUP BY source_ip ORDER BY cnt DESC LIMIT 50
            ''', (file_path, min_time))
            for row in cursor.fetchall():
                failed_ips[row[0]] = row[1]
            
            # Top失败用户
            cursor.execute(f'''
                SELECT user, COUNT(*) as cnt FROM {table_name}
                WHERE file_path = ? AND timestamp_unix >= ? 
                  AND result = 'failed' 
                  AND user IS NOT NULL AND user != ''
                GROUP BY user ORDER BY cnt DESC LIMIT 50
            ''', (file_path, min_time))
            for row in cursor.fetchall():
                failed_users[row[0]] = row[1]
            
            # Top成功用户
            cursor.execute(f'''
                SELECT user, COUNT(*) as cnt FROM {table_name}
                WHERE file_path = ? AND timestamp_unix >= ? 
                  AND result = 'success' 
                  AND user IS NOT NULL AND user != ''
                GROUP BY user ORDER BY cnt DESC LIMIT 50
            ''', (file_path, min_time))
            for row in cursor.fetchall():
                success_users[row[0]] = row[1]
            
            # Top Sudo用户
            cursor.execute(f'''
                SELECT user, COUNT(*) as cnt FROM {table_name}
                WHERE file_path = ? AND timestamp_unix >= ? 
                  AND event_type LIKE 'SUDO%'
                  AND user IS NOT NULL AND user != ''
                GROUP BY user ORDER BY cnt DESC LIMIT 50
            ''', (file_path, min_time))
            for row in cursor.fetchall():
                sudo_users[row[0]] = row[1]
            
            # 事件类型分布
            cursor.execute(f'''
                SELECT event_type, COUNT(*) as cnt FROM {table_name}
                WHERE file_path = ? AND timestamp_unix >= ?
                  AND event_type IS NOT NULL AND event_type != ''
                GROUP BY event_type ORDER BY cnt DESC
            ''', (file_path, min_time))
            for row in cursor.fetchall():
                event_types[row[0]] = row[1]
            
            # 时间趋势
            cursor.execute(f'''
                SELECT strftime('%Y-%m-%d %H:00', datetime(timestamp_unix, 'unixepoch')) as hour,
                       SUM(CASE WHEN result = 'success' THEN 1 ELSE 0 END) as success,
                       SUM(CASE WHEN result = 'failed' THEN 1 ELSE 0 END) as failed
                FROM {table_name}
                WHERE file_path = ? AND timestamp_unix >= ?
                GROUP BY hour ORDER BY hour
            ''', (file_path, min_time))
            for row in cursor.fetchall():
                hourly_data[row[0]] = {'hour': row[0], 'success': row[1] or 0, 'failed': row[2] or 0}
            
            conn.close()
            
            # 转换为列表
            stats["top_failed_ips"] = [{"ip": k, "count": v} for k, v in sorted(failed_ips.items(), key=lambda x: -x[1])[:50]]
            stats["top_failed_users"] = [{"user": k, "count": v} for k, v in sorted(failed_users.items(), key=lambda x: -x[1])[:50]]
            stats["top_success_users"] = [{"user": k, "count": v} for k, v in sorted(success_users.items(), key=lambda x: -x[1])[:50]]
            stats["top_sudo_users"] = [{"user": k, "count": v} for k, v in sorted(sudo_users.items(), key=lambda x: -x[1])[:50]]
            stats["event_type_distribution"] = [{"type": k, "count": v} for k, v in sorted(event_types.items(), key=lambda x: -x[1])]
            stats["hourly_timeline"] = sorted(hourly_data.values(), key=lambda x: x['hour'])
            
            return {"success": True, "statistics": stats}
            
        except Exception as e:
            print(f"[LinuxCache] 文件统计失败: {e}")
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    # 注意: get_login_statistics 已移至 statistics_service.py
    # 使用 StatisticsService.get_host_statistics() 代替
    
    def clear_cache(self, file_path: str = None, log_type: str = None, host_id: str = None):
        """清除缓存"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            if file_path:
                # 清除特定文件
                cursor.execute('SELECT table_name FROM file_cache_status WHERE file_path = ?', (file_path,))
                row = cursor.fetchone()
                if row:
                    cursor.execute(f'DELETE FROM {row[0]} WHERE file_path = ?', (file_path,))
                cursor.execute('DELETE FROM file_cache_status WHERE file_path = ?', (file_path,))
            elif log_type:
                # 清除特定类型
                table_name = self._get_table_name(log_type, host_id)
                cursor.execute(f'DROP TABLE IF EXISTS {table_name}')
                cursor.execute('DELETE FROM file_cache_status WHERE log_type = ?', (log_type,))
            else:
                # 清除所有
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'events_%'")
                for row in cursor.fetchall():
                    cursor.execute(f'DROP TABLE IF EXISTS {row[0]}')
                cursor.execute('DELETE FROM file_cache_status')
            
            conn.commit()
            conn.close()
            
            print(f"[LinuxCache] 缓存已清除")
            return {"success": True}
            
        except Exception as e:
            print(f"[LinuxCache] 清除缓存失败: {e}")
            return {"success": False, "error": str(e)}
    
    def get_cache_info(self) -> dict:
        """获取缓存信息"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            # 获取所有缓存文件
            cursor.execute('''
                SELECT file_path, log_type, host_id, event_count, cached_at, table_name
                FROM file_cache_status
            ''')
            
            files = []
            for row in cursor.fetchall():
                files.append({
                    "file_path": row[0],
                    "log_type": row[1],
                    "host_id": row[2],
                    "event_count": row[3],
                    "cached_at": row[4],
                    "table_name": row[5]
                })
            
            # 数据库大小
            db_size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
            
            conn.close()
            
            return {
                "success": True,
                "db_path": self.db_path,
                "db_size": db_size,
                "db_size_mb": round(db_size / 1024 / 1024, 2),
                "cached_files": len(files),
                "total_events": sum(f["event_count"] for f in files),
                "files": files
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
