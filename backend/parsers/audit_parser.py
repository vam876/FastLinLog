#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Audit日志解析器 - 增强版
格式: type=TYPE msg=audit(EPOCH.MS:SERIAL): [user] key=value msg='nested_kv'

增强功能:
- 完整解析msg字段内所有子字段
- 十六进制解码
- CRYPTO_KEY_USER专用字段解析
- SERVICE_*专用字段解析
- 计算字段生成
"""

import re
import os
from datetime import datetime
from typing import Optional, Dict, Any, List

from .base_parser import BaseParser
from ..core.log_event import LogEvent, EventLevel, EventResult


class AuditParser(BaseParser):
    """增强的审计日志解析器"""
    
    name = "audit"
    supported_types = ["audit"]
    
    # 主正则: type=TYPE msg=audit(EPOCH:SERIAL): data
    MAIN_PATTERN = re.compile(
        r'^type=(?P<type>\S+)\s+msg=audit\((?P<epoch>[\d.]+):(?P<serial>\d+)\):\s*(?P<data>.*)'
    )
    
    # 嵌套msg正则 - 匹配 msg='...'
    MSG_PATTERN = re.compile(r"msg='([^']*)'")
    
    # LOGIN特殊格式: pid=X uid=X old auid=X new auid=X old ses=X new ses=X
    LOGIN_PATTERN = re.compile(
        r'pid=(?P<pid>\d+)\s+uid=(?P<uid>\d+)\s+'
        r'old auid=(?P<old_auid>\d+)\s+new auid=(?P<new_auid>\d+)\s+'
        r'old ses=(?P<old_ses>\d+)\s+new ses=(?P<new_ses>\d+)'
    )
    
    # Error类型分类
    ERROR_TYPES = {
        'pattern_not_matched': '格式不匹配',
        'timestamp_parse_error': '时间戳解析错误',
        'data_parse_error': '数据解析错误',
        'field_conversion_error': '字段转换错误',
        'unknown_error': '未知错误',
    }
    
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
    
    # 审计类型映射
    AUDIT_TYPES = {
        # 用户认证
        'USER_LOGIN': ('用户登录', 'security_auth', EventLevel.INFO),
        'USER_LOGOUT': ('用户登出', 'security_auth', EventLevel.INFO),
        'USER_AUTH': ('用户认证', 'security_auth', EventLevel.INFO),
        'USER_ACCT': ('账户检查', 'session', EventLevel.INFO),
        'USER_START': ('会话开始', 'session', EventLevel.INFO),
        'USER_END': ('会话结束', 'session', EventLevel.INFO),
        'LOGIN': ('登录', 'security_auth', EventLevel.INFO),
        'USER_ERR': ('认证错误', 'security_auth', EventLevel.ERROR),
        
        # 凭证管理
        'CRED_ACQ': ('凭证获取', 'credential', EventLevel.INFO),
        'CRED_DISP': ('凭证释放', 'credential', EventLevel.INFO),
        'CRED_REFR': ('凭证刷新', 'credential', EventLevel.INFO),
        
        # 加密操作
        'CRYPTO_KEY_USER': ('SSH密钥操作', 'crypto', EventLevel.INFO),
        'CRYPTO_SESSION': ('加密会话', 'crypto', EventLevel.INFO),
        
        # 系统调用
        'SYSCALL': ('系统调用', 'other', EventLevel.INFO),
        'EXECVE': ('程序执行', 'other', EventLevel.INFO),
        'PATH': ('路径访问', 'other', EventLevel.INFO),
        'CWD': ('当前目录', 'other', EventLevel.INFO),
        'PROCTITLE': ('进程标题', 'other', EventLevel.INFO),
        
        # 配置变更
        'CONFIG_CHANGE': ('配置变更', 'other', EventLevel.WARNING),
        'DAEMON_START': ('守护进程启动', 'service', EventLevel.INFO),
        'DAEMON_END': ('守护进程停止', 'service', EventLevel.INFO),
        'SERVICE_START': ('服务启动', 'service', EventLevel.INFO),
        'SERVICE_STOP': ('服务停止', 'service', EventLevel.INFO),
        
        # 用户管理
        'USER_CHAUTHTOK': ('密码变更', 'other', EventLevel.WARNING),
        'ADD_USER': ('添加用户', 'other', EventLevel.WARNING),
        'DEL_USER': ('删除用户', 'other', EventLevel.WARNING),
        'ADD_GROUP': ('添加组', 'other', EventLevel.INFO),
        'DEL_GROUP': ('删除组', 'other', EventLevel.WARNING),
        'USER_MGMT': ('用户管理', 'other', EventLevel.INFO),
        'GRP_MGMT': ('组管理', 'other', EventLevel.INFO),
        'USER_ROLE_CHANGE': ('角色变更', 'other', EventLevel.INFO),
        
        # 安全相关
        'AVC': ('SELinux访问控制', 'other', EventLevel.WARNING),
        'SELINUX_ERR': ('SELinux错误', 'other', EventLevel.ERROR),
        'ANOM_PROMISCUOUS': ('网卡混杂模式', 'other', EventLevel.WARNING),
        'NETFILTER_CFG': ('防火墙配置', 'other', EventLevel.INFO),
        
        # 系统事件
        'SYSTEM_BOOT': ('系统启动', 'other', EventLevel.INFO),
        'SYSTEM_SHUTDOWN': ('系统关闭', 'other', EventLevel.INFO),
        'SYSTEM_RUNLEVEL': ('运行级别变更', 'other', EventLevel.INFO),
        
        # 命令执行
        'USER_CMD': ('用户命令', 'other', EventLevel.INFO),
    }
    
    def __init__(self, log_type: str = "audit"):
        super().__init__(log_type)
        self._parse_errors: List[Dict[str, Any]] = []
        self._parse_stats = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'skipped': 0
        }
        self._error_by_type: Dict[str, int] = {}
        self._source_file: str = ""
    
    def get_parse_stats(self) -> Dict[str, Any]:
        """
        获取解析统计
        
        Returns:
            包含以下字段的字典:
            - total: 总行数
            - success: 成功解析数
            - failed: 解析失败数
            - skipped: 跳过数（空行）
            - success_rate: 成功率（百分比）
            - failure_rate: 失败率（百分比）
            - error_by_type: 按错误类型分类的统计
        """
        stats = self._parse_stats.copy()
        
        # 计算成功率和失败率
        total_processed = stats['success'] + stats['failed']
        if total_processed > 0:
            stats['success_rate'] = round(stats['success'] / total_processed * 100, 2)
            stats['failure_rate'] = round(stats['failed'] / total_processed * 100, 2)
        else:
            stats['success_rate'] = 0.0
            stats['failure_rate'] = 0.0
        
        # 添加错误类型统计
        stats['error_by_type'] = self._error_by_type.copy()
        
        return stats
    
    def get_parse_errors(self, limit: int = None) -> List[Dict[str, Any]]:
        """
        获取解析错误列表
        
        Args:
            limit: 返回的最大错误数量，None表示返回全部
            
        Returns:
            错误列表，每个错误包含:
            - line_num: 行号
            - error_type: 错误类型代码
            - error_type_name: 错误类型中文名
            - reason: 详细原因
            - line: 原始行内容（截断）
            - source_file: 来源文件
        """
        errors = self._parse_errors.copy()
        if limit is not None and limit > 0:
            errors = errors[:limit]
        return errors
    
    def get_error_summary(self) -> Dict[str, Any]:
        """
        获取错误摘要报告
        
        Returns:
            包含以下字段的字典:
            - total_errors: 总错误数
            - error_types: 按类型分类的错误统计
            - sample_errors: 每种类型的示例错误（最多3个）
            - success_rate: 成功率
        """
        summary = {
            'total_errors': len(self._parse_errors),
            'error_types': {},
            'sample_errors': {},
            'success_rate': self.get_parse_stats().get('success_rate', 0.0)
        }
        
        # 按错误类型分组
        for error in self._parse_errors:
            error_type = error.get('error_type', 'unknown_error')
            if error_type not in summary['error_types']:
                summary['error_types'][error_type] = {
                    'count': 0,
                    'name': self.ERROR_TYPES.get(error_type, error_type)
                }
                summary['sample_errors'][error_type] = []
            
            summary['error_types'][error_type]['count'] += 1
            
            # 保存示例错误（每种类型最多3个）
            if len(summary['sample_errors'][error_type]) < 3:
                summary['sample_errors'][error_type].append({
                    'line_num': error.get('line_num'),
                    'reason': error.get('reason'),
                    'line_preview': error.get('line', '')[:100]
                })
        
        return summary
    
    def reset_stats(self):
        """重置统计"""
        self._parse_errors = []
        self._parse_stats = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'skipped': 0
        }
        self._error_by_type = {}
    
    def set_source_file(self, file_path: str):
        """设置当前解析的源文件路径"""
        self._source_file = file_path
    
    def _record_error(self, line_num: int, error_type: str, reason: str, line: str):
        """
        记录解析错误
        
        Args:
            line_num: 行号
            error_type: 错误类型代码
            reason: 详细原因
            line: 原始行内容
        """
        self._parse_errors.append({
            'line_num': line_num,
            'error_type': error_type,
            'error_type_name': self.ERROR_TYPES.get(error_type, error_type),
            'reason': reason,
            'line': line[:200] if line else '',
            'source_file': self._source_file
        })
        
        # 更新错误类型统计
        if error_type not in self._error_by_type:
            self._error_by_type[error_type] = 0
        self._error_by_type[error_type] += 1

    def decode_hex_value(self, value: str) -> str:
        """
        解码十六进制编码的值
        
        Args:
            value: 可能是十六进制编码的字符串
            
        Returns:
            解码后的字符串，解码失败时返回原始值
        """
        if not value:
            return value
        
        # 如果值是纯数字，不进行十六进制解码（避免将数字如74解码为't'）
        if value.isdigit():
            return value
        
        # 检测是否为十六进制编码（全部是十六进制字符且长度为偶数且长度>=4）
        # 长度>=4是为了避免将短的数值误解码
        if len(value) >= 4 and len(value) % 2 == 0:
            # 检查是否全部是十六进制字符（0-9, a-f, A-F）
            if all(c in '0123456789abcdefABCDEF' for c in value):
                try:
                    # 尝试解码
                    decoded = bytes.fromhex(value).decode('utf-8', errors='replace')
                    # 检查解码结果是否为可打印字符
                    if decoded and all(c.isprintable() or c.isspace() for c in decoded):
                        return decoded
                except (ValueError, UnicodeDecodeError):
                    pass
        
        return value
    
    def parse_msg_field(self, msg_content: str) -> Dict[str, Any]:
        """
        解析msg='...'内部的键值对
        
        支持的字段:
        - op: 操作类型
        - acct: 账户名
        - exe: 执行程序路径
        - hostname: 主机名
        - addr: 来源IP地址
        - terminal: 终端类型
        - res: 执行结果
        - grantors: PAM授权模块
        - id: 用户ID
        - fp: 密钥指纹
        - kind: 密钥类型
        - direction: 方向
        - spid: 子进程ID
        - suid: 子进程UID
        - laddr: 本地地址
        - lport: 本地端口
        - rport: 远程端口
        - cipher: 加密算法
        - ksize: 密钥大小
        - unit: systemd单元名
        - comm: 命令名
        
        Args:
            msg_content: msg字段内容（不含外层引号）
            
        Returns:
            解析后的字典
        """
        result = {}
        
        if not msg_content:
            return result
        
        # 使用状态机解析键值对，正确处理引号内的空格
        i = 0
        n = len(msg_content)
        
        while i < n:
            # 跳过空白
            while i < n and msg_content[i] in ' \t':
                i += 1
            
            if i >= n:
                break
            
            # 读取键名
            key_start = i
            while i < n and msg_content[i] not in '= \t':
                i += 1
            
            if i >= n or msg_content[i] != '=':
                # 没有找到等号，跳过这个token
                while i < n and msg_content[i] not in ' \t':
                    i += 1
                continue
            
            key = msg_content[key_start:i]
            i += 1  # 跳过等号
            
            if i >= n:
                result[key] = ''
                break
            
            # 读取值
            if msg_content[i] == '"':
                # 双引号包围的值
                i += 1
                value_start = i
                while i < n and msg_content[i] != '"':
                    i += 1
                value = msg_content[value_start:i]
                if i < n:
                    i += 1  # 跳过结束引号
            elif msg_content[i] == "'":
                # 单引号包围的值
                i += 1
                value_start = i
                while i < n and msg_content[i] != "'":
                    i += 1
                value = msg_content[value_start:i]
                if i < n:
                    i += 1  # 跳过结束引号
            else:
                # 无引号的值，读取到空格为止
                value_start = i
                while i < n and msg_content[i] not in ' \t':
                    i += 1
                value = msg_content[value_start:i]
            
            # 处理'?'值标记为空
            if value == '?':
                value = ''
            
            # 尝试十六进制解码
            value = self.decode_hex_value(value)
            
            # 转换值类型
            result[key] = self._convert_value(key, value)
        
        return result
    
    def _convert_value(self, key: str, value: str) -> Any:
        """转换值类型"""
        if value is None or value == '':
            return value
        
        # 数字字段
        int_fields = ['pid', 'uid', 'auid', 'ses', 'id', 'spid', 'suid', 
                      'rport', 'lport', 'ksize', 'old_auid', 'new_auid',
                      'old_ses', 'new_ses']
        if key in int_fields:
            try:
                return int(value)
            except (ValueError, TypeError):
                pass
        
        return value
    
    def get_event_category(self, audit_type: str) -> str:
        """
        获取事件分类
        
        Args:
            audit_type: 审计事件类型
            
        Returns:
            分类名称（security_auth, credential, session, crypto, service, other）
        """
        for category, types in self.EVENT_CATEGORIES.items():
            if audit_type in types:
                return category
        return 'other'
    
    def generate_computed_fields(self, event: LogEvent, parsed: Dict) -> None:
        """
        生成计算字段
        
        设置以下字段:
        - user_display: 优先acct，其次uid映射，最后auid
        - exe_short: exe路径的basename
        - is_success: res == 'success'
        - is_remote: addr非空且不为'?'
        """
        # user_display: 优先acct，其次uid，最后auid
        acct = parsed.get('acct', '')
        if acct and acct != '?':
            event.user_display = acct
        elif event.uid is not None and event.uid != 4294967295:
            event.user_display = str(event.uid)
        elif event.auid is not None and event.auid != 4294967295:
            event.user_display = str(event.auid)
        else:
            event.user_display = ''
        
        # exe_short: exe路径的basename
        exe = parsed.get('exe', '').strip('"')
        if exe:
            event.exe_short = os.path.basename(exe)
        else:
            event.exe_short = ''
        
        # is_success: res == 'success'
        res = parsed.get('res', '')
        event.is_success = (res == 'success')
        
        # is_remote: addr非空且不为'?'
        addr = parsed.get('addr', '')
        event.is_remote = bool(addr and addr != '?')

    def _parse_crypto_fields(self, event: LogEvent, parsed: Dict) -> None:
        """解析CRYPTO_KEY_USER和CRYPTO_SESSION专用字段"""
        event.crypto_fp = parsed.get('fp', '')
        event.crypto_kind = parsed.get('kind', '')
        event.crypto_direction = parsed.get('direction', '')
        
        spid = parsed.get('spid')
        if spid is not None:
            event.crypto_spid = int(spid) if isinstance(spid, str) else spid
        
        suid = parsed.get('suid')
        if suid is not None:
            event.crypto_suid = int(suid) if isinstance(suid, str) else suid
        
        event.crypto_laddr = parsed.get('laddr', '')
        
        lport = parsed.get('lport')
        if lport is not None:
            try:
                event.crypto_lport = int(lport) if isinstance(lport, str) else lport
            except (ValueError, TypeError):
                pass
        
        rport = parsed.get('rport')
        if rport is not None:
            try:
                event.crypto_rport = int(rport) if isinstance(rport, str) else rport
            except (ValueError, TypeError):
                pass
        
        event.crypto_cipher = parsed.get('cipher', '')
        
        ksize = parsed.get('ksize')
        if ksize is not None:
            try:
                event.crypto_ksize = int(ksize) if isinstance(ksize, str) else ksize
            except (ValueError, TypeError):
                pass
    
    def _parse_service_fields(self, event: LogEvent, parsed: Dict) -> None:
        """解析SERVICE_*专用字段"""
        event.service_unit = parsed.get('unit', '')
        event.service_comm = parsed.get('comm', '')
    
    def _parse_data(self, data: str, audit_type: str) -> Dict[str, Any]:
        """解析数据部分"""
        result = {}
        
        # 特殊处理LOGIN类型
        if audit_type == 'LOGIN':
            login_match = self.LOGIN_PATTERN.search(data)
            if login_match:
                result['pid'] = int(login_match.group('pid'))
                result['uid'] = int(login_match.group('uid'))
                result['old_auid'] = int(login_match.group('old_auid'))
                result['auid'] = int(login_match.group('new_auid'))
                result['old_ses'] = int(login_match.group('old_ses'))
                result['ses'] = int(login_match.group('new_ses'))
                return result
        
        # 提取 "user" 前缀的pid/uid等
        user_prefix = re.match(r'^user\s+', data)
        if user_prefix:
            data = data[user_prefix.end():]
        
        # 先提取嵌套的msg
        msg_match = self.MSG_PATTERN.search(data)
        if msg_match:
            msg_content = msg_match.group(1)
            msg_parsed = self.parse_msg_field(msg_content)
            result.update(msg_parsed)
        
        # 解析主数据的键值对（外层字段）
        outer_parsed = self.parse_msg_field(data.replace(msg_match.group(0), '') if msg_match else data)
        for key, value in outer_parsed.items():
            if key not in result:  # 不覆盖msg中的值
                result[key] = value
        
        return result
    
    def parse_line(self, line: str, record_id: int = 0) -> Optional[LogEvent]:
        """解析单行audit日志"""
        self._parse_stats['total'] += 1
        
        if not line.strip():
            self._parse_stats['skipped'] += 1
            return None
        
        match = self.MAIN_PATTERN.match(line)
        if not match:
            self._parse_stats['failed'] += 1
            self._record_error(
                line_num=record_id,
                error_type='pattern_not_matched',
                reason='日志行格式不匹配audit日志模式',
                line=line
            )
            return None
        
        try:
            audit_type = match.group('type')
            epoch_str = match.group('epoch')
            serial = int(match.group('serial'))
            data = match.group('data')
            
            # Parse time戳
            try:
                if '.' in epoch_str:
                    epoch, usec = epoch_str.split('.')
                    epoch = int(epoch)
                    usec = int(usec.ljust(6, '0')[:6])  # 补齐到微秒
                else:
                    epoch = int(epoch_str)
                    usec = 0
            except Exception as ts_err:
                # 时间戳解析失败，记录但继续处理
                self._record_error(
                    line_num=record_id,
                    error_type='timestamp_parse_error',
                    reason=f'时间戳解析失败: {str(ts_err)}',
                    line=line
                )
                epoch, usec = 0, 0
            
            # Create event
            event = LogEvent(
                record_id=record_id,
                log_type=self.log_type,
                audit_type=audit_type,
                audit_serial=serial,
            )
            
            # Set time戳
            event.set_timestamp(unix_ts=epoch, usec=usec)
            
            # 解析数据部分
            try:
                parsed = self._parse_data(data, audit_type)
            except Exception as data_err:
                self._parse_stats['failed'] += 1
                self._record_error(
                    line_num=record_id,
                    error_type='data_parse_error',
                    reason=f'数据解析失败: {str(data_err)}',
                    line=line
                )
                return None
            
            # 填充基础字段
            try:
                event.pid = parsed.get('pid')
                event.uid = parsed.get('uid')
                event.auid = parsed.get('auid')
                event.session_id = parsed.get('ses')
                event.subj = parsed.get('subj', '')
                
                # 填充msg内部字段
                event.user = parsed.get('acct', '')
                event.audit_acct = parsed.get('acct', '')
                event.hostname = parsed.get('hostname', '')
                event.source_ip = parsed.get('addr', '')
                event.terminal = parsed.get('terminal', '')
                event.exe = parsed.get('exe', '').strip('"')
                event.operation = parsed.get('op', '')
                event.audit_op = parsed.get('op', '')
                event.grantors = parsed.get('grantors', '')
                event.process = event.exe.split('/')[-1] if event.exe else ''
                
                # 解析id字段（LOGIN类型）
                id_val = parsed.get('id')
                if id_val is not None:
                    try:
                        event.audit_id = int(id_val) if isinstance(id_val, str) else id_val
                    except (ValueError, TypeError):
                        pass
                
                # 解析结果
                res = parsed.get('res', '')
                if res == 'success':
                    event.result = EventResult.SUCCESS
                elif res == 'failed':
                    event.result = EventResult.FAILED
                
                # 设置事件类型信息
                type_info = self.AUDIT_TYPES.get(audit_type, (audit_type, 'other', EventLevel.INFO))
                event.event_type = audit_type
                event.event_name = type_info[0]
                event.event_category = self.CATEGORY_NAMES.get(type_info[1], type_info[1])
                event.level = type_info[2]
                
                # 解析CRYPTO专用字段
                if audit_type in ['CRYPTO_KEY_USER', 'CRYPTO_SESSION']:
                    self._parse_crypto_fields(event, parsed)
                
                # 解析SERVICE专用字段
                if audit_type.startswith('SERVICE_') or audit_type in ['DAEMON_START', 'DAEMON_END']:
                    self._parse_service_fields(event, parsed)
                
                # 生成计算字段
                self.generate_computed_fields(event, parsed)
                
                # 构建消息
                event.message = self._build_message(event, parsed)
                
                # 存储额外数据
                excluded_keys = ['pid', 'uid', 'auid', 'ses', 'acct', 'hostname', 
                               'addr', 'terminal', 'exe', 'op', 'res', 'subj',
                               'grantors', 'id', 'fp', 'kind', 'direction', 'spid',
                               'suid', 'laddr', 'lport', 'rport', 'cipher', 'ksize',
                               'unit', 'comm']
                event.extra = {k: v for k, v in parsed.items() if k not in excluded_keys}
                
            except Exception as field_err:
                self._parse_stats['failed'] += 1
                self._record_error(
                    line_num=record_id,
                    error_type='field_conversion_error',
                    reason=f'字段转换失败: {str(field_err)}',
                    line=line
                )
                return None
            
            self._parse_stats['success'] += 1
            return event
            
        except Exception as e:
            self._parse_stats['failed'] += 1
            self._record_error(
                line_num=record_id,
                error_type='unknown_error',
                reason=str(e),
                line=line
            )
            return None
    
    def _build_message(self, event: LogEvent, parsed: Dict) -> str:
        """构建消息描述"""
        parts = []
        
        if event.operation:
            parts.append(f"操作:{event.operation}")
        if event.user_display:
            parts.append(f"用户:{event.user_display}")
        if event.source_ip:
            parts.append(f"来源:{event.source_ip}")
        if event.terminal:
            parts.append(f"终端:{event.terminal}")
        if event.result:
            parts.append(f"结果:{'成功' if event.result == 'success' else '失败'}")
        
        # SERVICE事件添加unit信息
        if event.service_unit:
            parts.append(f"服务:{event.service_unit}")
        
        return ' | '.join(parts) if parts else event.event_name
    
    def get_fields(self):
        """获取audit特有字段"""
        base = super().get_fields()
        audit_fields = [
            {"name": "audit_type", "label": "审计类型", "type": "string"},
            {"name": "audit_serial", "label": "序列号", "type": "number"},
            {"name": "auid", "label": "审计UID", "type": "number"},
            {"name": "session_id", "label": "会话ID", "type": "number"},
            {"name": "exe", "label": "执行程序", "type": "string"},
            {"name": "exe_short", "label": "程序名", "type": "string"},
            {"name": "terminal", "label": "终端", "type": "string"},
            {"name": "operation", "label": "操作", "type": "string"},
            {"name": "user_display", "label": "用户", "type": "string"},
            {"name": "is_success", "label": "成功", "type": "boolean"},
            {"name": "is_remote", "label": "远程", "type": "boolean"},
            {"name": "grantors", "label": "授权模块", "type": "string"},
            {"name": "subj", "label": "SELinux主体", "type": "string"},
        ]
        return base + audit_fields
    
    def parse_file(self, file_path: str, encoding: str = 'utf-8', reset_stats: bool = True):
        """
        解析日志文件（增强版，支持错误统计）
        
        Args:
            file_path: 文件路径
            encoding: 文件编码
            reset_stats: 是否重置统计（默认True）
            
        Yields:
            LogEvent
        """
        from pathlib import Path
        
        path = Path(file_path)
        if not path.exists():
            return
        
        # 设置源文件并可选重置统计
        self.set_source_file(str(file_path))
        if reset_stats:
            self.reset_stats()
        
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
                            event.source_file = str(file_path)
                            yield event
                break
            except UnicodeDecodeError:
                continue
            except Exception as e:
                print(f"解析文件错误 {file_path}: {e}")
                break
    
    def print_parse_report(self):
        """打印解析报告（用于调试）"""
        stats = self.get_parse_stats()
        summary = self.get_error_summary()
        
        print("\n" + "=" * 60)
        print("审计日志解析报告")
        print("=" * 60)
        print(f"总行数: {stats['total']}")
        print(f"成功解析: {stats['success']}")
        print(f"解析失败: {stats['failed']}")
        print(f"跳过(空行): {stats['skipped']}")
        print(f"成功率: {stats['success_rate']:.2f}%")
        print(f"失败率: {stats['failure_rate']:.2f}%")
        
        if summary['total_errors'] > 0:
            print("\n错误类型统计:")
            for error_type, info in summary['error_types'].items():
                print(f"  - {info['name']}: {info['count']}次")
            
            print("\n错误示例:")
            for error_type, samples in summary['sample_errors'].items():
                if samples:
                    print(f"\n  [{self.ERROR_TYPES.get(error_type, error_type)}]")
                    for sample in samples[:2]:
                        print(f"    行 {sample['line_num']}: {sample['reason']}")
                        if sample['line_preview']:
                            print(f"    内容: {sample['line_preview'][:80]}...")
        
        print("=" * 60)
