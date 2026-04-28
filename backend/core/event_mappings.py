#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Linux日志事件类型映射配置
集中管理所有事件类型的定义、名称、分类和级别
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Tuple, Optional


class EventLevel(Enum):
    """事件级别"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventResult(Enum):
    """事件结果"""
    SUCCESS = "success"
    FAILED = "failed"
    DENIED = "denied"
    UNKNOWN = ""


@dataclass
class EventTypeInfo:
    """事件类型信息"""
    name: str           # 中文名称
    category: str       # 事件分类
    level: EventLevel   # 事件级别
    result: str         # 默认结果
    description: str = ""  # 详细描述


# ==================== SSH事件映射 ====================
SSH_EVENTS: Dict[str, EventTypeInfo] = {
    # 认证成功
    'SSH_ACCEPTED_PASSWORD': EventTypeInfo(
        'SSH密码登录成功', '认证', EventLevel.INFO, 'success',
        '用户通过密码方式成功登录SSH'
    ),
    'SSH_ACCEPTED_PUBLICKEY': EventTypeInfo(
        'SSH公钥登录成功', '认证', EventLevel.INFO, 'success',
        '用户通过公钥方式成功登录SSH'
    ),
    'SSH_ACCEPTED_KEYBOARD': EventTypeInfo(
        'SSH键盘交互登录成功', '认证', EventLevel.INFO, 'success',
        '用户通过键盘交互方式(如PAM)成功登录SSH'
    ),
    'SSH_ACCEPTED_GSSAPI': EventTypeInfo(
        'SSH GSSAPI登录成功', '认证', EventLevel.INFO, 'success',
        '用户通过GSSAPI/Kerberos方式成功登录SSH'
    ),
    'SSH_ACCEPTED_HOSTBASED': EventTypeInfo(
        'SSH主机认证登录成功', '认证', EventLevel.INFO, 'success',
        '用户通过主机认证方式成功登录SSH'
    ),
    
    # 认证失败
    'SSH_FAILED_PASSWORD': EventTypeInfo(
        'SSH密码登录失败', '认证', EventLevel.WARNING, 'failed',
        '用户密码认证失败，可能是密码错误'
    ),
    'SSH_FAILED_PUBLICKEY': EventTypeInfo(
        'SSH公钥登录失败', '认证', EventLevel.WARNING, 'failed',
        '用户公钥认证失败'
    ),
    'SSH_INVALID_USER': EventTypeInfo(
        '无效用户登录尝试', '认证', EventLevel.WARNING, 'failed',
        '尝试使用不存在的用户名登录'
    ),
    'SSH_AUTH_FAILURE': EventTypeInfo(
        'SSH认证失败', '认证', EventLevel.WARNING, 'failed',
        'PAM认证失败'
    ),
    'SSH_MAX_AUTH': EventTypeInfo(
        '认证尝试超限', '安全', EventLevel.WARNING, 'failed',
        '超过最大认证尝试次数'
    ),
    'SSH_TOO_MANY_AUTH': EventTypeInfo(
        '认证失败过多断开', '安全', EventLevel.WARNING, 'failed',
        '因认证失败次数过多被断开连接'
    ),
    'SSH_PAM_CHECK_PASS': EventTypeInfo(
        'PAM密码检查失败', '认证', EventLevel.WARNING, 'failed',
        'PAM密码检查失败，用户未知'
    ),
    'SSH_PAM_MORE_FAILURES': EventTypeInfo(
        'PAM更多认证失败', '认证', EventLevel.WARNING, 'failed',
        'PAM记录更多认证失败'
    ),
    'SSH_PREAUTH_INVALID_USER': EventTypeInfo(
        '预认证无效用户', '认证', EventLevel.WARNING, 'failed',
        '预认证阶段检测到无效用户'
    ),
    
    # 会话管理
    'SSH_SESSION_OPENED': EventTypeInfo(
        'SSH会话开启', '会话', EventLevel.INFO, 'success',
        'SSH会话成功开启'
    ),
    'SSH_SESSION_CLOSED': EventTypeInfo(
        'SSH会话关闭', '会话', EventLevel.INFO, 'success',
        'SSH会话正常关闭'
    ),
    'SSH_SFTP_SUBSYSTEM': EventTypeInfo(
        'SFTP子系统请求', '会话', EventLevel.INFO, 'success',
        '请求SFTP子系统'
    ),
    'SSH_NO_MORE_SESSIONS': EventTypeInfo(
        '无更多会话', '会话', EventLevel.INFO, '',
        '没有更多可用会话'
    ),
    
    # 连接管理
    'SSH_CONNECTION_CLOSED': EventTypeInfo(
        'SSH连接关闭', '连接', EventLevel.INFO, '',
        'SSH连接被关闭'
    ),
    'SSH_DISCONNECTED': EventTypeInfo(
        'SSH断开连接', '连接', EventLevel.INFO, '',
        'SSH连接断开'
    ),
    'SSH_DISCONNECTED_BY_USER': EventTypeInfo(
        '用户断开连接', '连接', EventLevel.INFO, '',
        '用户主动断开SSH连接'
    ),
    'SSH_CONNECTION_RESET': EventTypeInfo(
        '连接重置', '连接', EventLevel.INFO, '',
        'SSH连接被重置'
    ),
    'SSH_CONNECTION_RESET_PEER': EventTypeInfo(
        '连接被对端重置', '连接', EventLevel.INFO, '',
        'SSH连接被对端重置'
    ),
    'SSH_RECEIVED_DISCONNECT': EventTypeInfo(
        '收到断开请求', '连接', EventLevel.INFO, '',
        '收到SSH断开连接请求'
    ),
    
    # 安全事件
    'SSH_NO_IDENT': EventTypeInfo(
        '未收到身份标识', '安全', EventLevel.WARNING, '',
        '未收到SSH协议身份标识字符串'
    ),
    'SSH_BAD_PROTOCOL': EventTypeInfo(
        '协议版本错误', '安全', EventLevel.WARNING, '',
        'SSH协议版本标识错误'
    ),
    'SSH_BREAK_IN': EventTypeInfo(
        '可能的入侵尝试', '安全', EventLevel.CRITICAL, '',
        '反向DNS解析失败，可能是入侵尝试'
    ),
    'SSH_KEY_NEGOTIATE': EventTypeInfo(
        '密钥协商失败', '安全', EventLevel.WARNING, 'failed',
        '无法协商密钥交换方法'
    ),
    'SSH_REFUSED_CONNECT': EventTypeInfo(
        '拒绝连接', '安全', EventLevel.WARNING, 'denied',
        '拒绝来自特定主机的连接'
    ),
    'SSH_PAM_IGNORING_RETRIES': EventTypeInfo(
        'PAM忽略重试限制', '安全', EventLevel.WARNING, '',
        'PAM忽略最大重试限制'
    ),
    'SSH_INCOMPLETE_MESSAGE': EventTypeInfo(
        '不完整消息', '安全', EventLevel.WARNING, '',
        '收到不完整的SSH消息'
    ),
    'SSH_DH_GEX_OUT_OF_RANGE': EventTypeInfo(
        'DH密钥交换范围错误', '安全', EventLevel.WARNING, 'failed',
        'DH密钥交换参数超出范围'
    ),
    'SSH_UID_REQUIREMENT': EventTypeInfo(
        'UID要求不满足', '认证', EventLevel.INFO, '',
        '用户UID不满足要求'
    ),
    'SSH_PAM_AUTH_FAILURE': EventTypeInfo(
        'PAM认证失败', '认证', EventLevel.WARNING, 'failed',
        'PAM认证失败'
    ),
    'SSH_ACCOUNT_LOCKED': EventTypeInfo(
        '账户已锁定', '认证', EventLevel.WARNING, 'failed',
        '用户账户已锁定或过期'
    ),
    'SSH_FAILED_LOCKED_USER': EventTypeInfo(
        '锁定用户登录失败', '认证', EventLevel.WARNING, 'failed',
        '锁定用户尝试登录失败'
    ),
    'SSH_INVALID_USER_EMPTY': EventTypeInfo(
        '空用户名登录尝试', '认证', EventLevel.WARNING, 'failed',
        '使用空用户名尝试登录'
    ),
    
    # 服务事件
    'SSH_SERVER_LISTENING': EventTypeInfo(
        'SSH服务启动', '服务', EventLevel.INFO, 'success',
        'SSH服务开始监听'
    ),
    
    # 其他
    'SSH_OTHER': EventTypeInfo(
        'SSH其他事件', 'SSH', EventLevel.INFO, '',
        '未分类的SSH事件'
    ),
}

# ==================== Sudo事件映射 ====================
SUDO_EVENTS: Dict[str, EventTypeInfo] = {
    'SUDO_COMMAND': EventTypeInfo(
        'Sudo命令执行', '权限', EventLevel.INFO, 'success',
        '用户通过sudo执行命令'
    ),
    'SUDO_NOT_IN_SUDOERS': EventTypeInfo(
        'Sudo权限拒绝', '权限', EventLevel.CRITICAL, 'denied',
        '用户不在sudoers文件中，权限被拒绝'
    ),
    'SUDO_SESSION_OPENED': EventTypeInfo(
        'Sudo会话开启', '会话', EventLevel.INFO, 'success',
        'Sudo会话成功开启'
    ),
    'SUDO_SESSION_CLOSED': EventTypeInfo(
        'Sudo会话关闭', '会话', EventLevel.INFO, 'success',
        'Sudo会话正常关闭'
    ),
    'SUDO_AUTH_FAILURE': EventTypeInfo(
        'Sudo认证失败', '权限', EventLevel.WARNING, 'failed',
        'Sudo密码认证失败'
    ),
    'SUDO_INCORRECT_PASSWORD': EventTypeInfo(
        'Sudo密码错误', '权限', EventLevel.WARNING, 'failed',
        'Sudo输入了错误的密码'
    ),
    'SUDO_3_INCORRECT_ATTEMPTS': EventTypeInfo(
        'Sudo密码错误3次', '权限', EventLevel.WARNING, 'failed',
        'Sudo连续3次密码错误'
    ),
}

# ==================== SU事件映射 ====================
SU_EVENTS: Dict[str, EventTypeInfo] = {
    'SU_TO_USER': EventTypeInfo(
        '切换用户', '权限', EventLevel.INFO, 'success',
        '使用su命令切换到其他用户'
    ),
    'SU_SESSION_OPENED': EventTypeInfo(
        'SU会话开启', '会话', EventLevel.INFO, 'success',
        'SU会话成功开启'
    ),
    'SU_SESSION_CLOSED': EventTypeInfo(
        'SU会话关闭', '会话', EventLevel.INFO, 'success',
        'SU会话正常关闭'
    ),
    'SU_FAILED': EventTypeInfo(
        'SU切换失败', '权限', EventLevel.WARNING, 'failed',
        'SU切换用户失败'
    ),
    'SU_AUTH_FAILURE': EventTypeInfo(
        'SU认证失败', '权限', EventLevel.WARNING, 'failed',
        'SU密码认证失败'
    ),
    'SU_BAD_SU': EventTypeInfo(
        'SU失败记录', '权限', EventLevel.WARNING, 'failed',
        'SU切换失败的详细记录'
    ),
}

# ==================== CRON事件映射 ====================
CRON_EVENTS: Dict[str, EventTypeInfo] = {
    'CRON_SESSION_OPENED': EventTypeInfo(
        'Cron会话开启', '定时任务', EventLevel.INFO, 'success',
        'Cron任务会话开启'
    ),
    'CRON_SESSION_CLOSED': EventTypeInfo(
        'Cron会话关闭', '定时任务', EventLevel.INFO, 'success',
        'Cron任务会话关闭'
    ),
    'CRON_CMD': EventTypeInfo(
        'Cron命令执行', '定时任务', EventLevel.INFO, 'success',
        'Cron执行定时任务命令'
    ),
    'CRON_STARTUP': EventTypeInfo(
        'Cron服务启动', '定时任务', EventLevel.INFO, 'success',
        'Cron服务启动'
    ),
}

# ==================== 用户管理事件映射 ====================
USER_MGMT_EVENTS: Dict[str, EventTypeInfo] = {
    'USER_ADD': EventTypeInfo(
        '创建用户', '用户管理', EventLevel.INFO, 'success',
        '创建新用户账户'
    ),
    'USER_DEL': EventTypeInfo(
        '删除用户', '用户管理', EventLevel.WARNING, 'success',
        '删除用户账户'
    ),
    'USER_MOD': EventTypeInfo(
        '修改用户', '用户管理', EventLevel.INFO, 'success',
        '修改用户账户属性'
    ),
    'USER_ADD_TO_GROUP': EventTypeInfo(
        '用户加组', '用户管理', EventLevel.INFO, 'success',
        '将用户添加到组'
    ),
    'GROUP_ADD': EventTypeInfo(
        '创建组', '用户管理', EventLevel.INFO, 'success',
        '创建新用户组'
    ),
    'GROUP_DEL': EventTypeInfo(
        '删除组', '用户管理', EventLevel.WARNING, 'success',
        '删除用户组'
    ),
    'NEW_GROUP': EventTypeInfo(
        '新建组', '用户管理', EventLevel.INFO, 'success',
        '创建新用户组(groupadd)'
    ),
    'PASSWD_CHANGED': EventTypeInfo(
        '密码修改', '用户管理', EventLevel.INFO, 'success',
        '用户密码被修改'
    ),
    'PASSWD_CHANGE_FAILED': EventTypeInfo(
        '密码修改失败', '用户管理', EventLevel.WARNING, 'failed',
        '用户密码修改失败'
    ),
    'PASSWORD_CHECK_FAILED': EventTypeInfo(
        '密码检查失败', '认证', EventLevel.WARNING, 'failed',
        '密码检查失败'
    ),
}

# ==================== 本地登录事件映射 ====================
LOGIN_EVENTS: Dict[str, EventTypeInfo] = {
    'ROOT_LOGIN': EventTypeInfo(
        'Root本地登录', '认证', EventLevel.WARNING, 'success',
        'Root用户本地登录'
    ),
    'ROOT_LOGIN_ON': EventTypeInfo(
        'Root终端登录', '认证', EventLevel.WARNING, 'success',
        'Root用户在终端登录'
    ),
    'LOGIN_SESSION_OPENED': EventTypeInfo(
        '本地登录会话开启', '会话', EventLevel.INFO, 'success',
        '本地登录会话开启'
    ),
    'LOGIN_SESSION_CLOSED': EventTypeInfo(
        '本地登录会话关闭', '会话', EventLevel.INFO, 'success',
        '本地登录会话关闭'
    ),
    'FAILED_LOGIN': EventTypeInfo(
        '本地登录失败', '认证', EventLevel.WARNING, 'failed',
        '本地登录认证失败'
    ),
    'LOGIN_AUTH_FAILURE': EventTypeInfo(
        '本地认证失败', '认证', EventLevel.WARNING, 'failed',
        '本地PAM认证失败'
    ),
}

# ==================== Systemd事件映射 ====================
SYSTEMD_EVENTS: Dict[str, EventTypeInfo] = {
    'SYSTEMD_NEW_SESSION': EventTypeInfo(
        '新会话创建', '会话', EventLevel.INFO, 'success',
        'systemd-logind创建新会话'
    ),
    'SYSTEMD_REMOVED_SESSION': EventTypeInfo(
        '会话移除', '会话', EventLevel.INFO, 'success',
        'systemd-logind移除会话'
    ),
    'SYSTEMD_STARTING_SESSION': EventTypeInfo(
        '会话启动中', '会话', EventLevel.INFO, '',
        'systemd正在启动会话'
    ),
    'SYSTEMD_SLICE_CREATED': EventTypeInfo(
        'Slice创建', '系统', EventLevel.INFO, 'success',
        'systemd创建slice'
    ),
    'SYSTEMD_SLICE_REMOVED': EventTypeInfo(
        'Slice移除', '系统', EventLevel.INFO, 'success',
        'systemd移除slice'
    ),
    'SYSTEMD_SLICE_STOPPING': EventTypeInfo(
        'Slice停止中', '系统', EventLevel.INFO, '',
        'systemd正在停止slice'
    ),
    'SYSTEMD_SLICE': EventTypeInfo(
        'Slice操作', '系统', EventLevel.INFO, '',
        'systemd slice操作'
    ),
    'SYSTEMD_SERVICE_START': EventTypeInfo(
        '服务启动', '系统', EventLevel.INFO, 'success',
        'systemd启动服务'
    ),
    'SYSTEMD_SERVICE_STOP': EventTypeInfo(
        '服务停止', '系统', EventLevel.INFO, 'success',
        'systemd停止服务'
    ),
}

# ==================== PolicyKit事件映射 ====================
POLKIT_EVENTS: Dict[str, EventTypeInfo] = {
    'POLKIT': EventTypeInfo(
        'PolicyKit认证', '权限', EventLevel.INFO, '',
        'PolicyKit权限认证事件'
    ),
    'POLKIT_AUTH_SUCCESS': EventTypeInfo(
        'PolicyKit认证成功', '权限', EventLevel.INFO, 'success',
        'PolicyKit权限认证成功'
    ),
    'POLKIT_AUTH_FAILED': EventTypeInfo(
        'PolicyKit认证失败', '权限', EventLevel.WARNING, 'failed',
        'PolicyKit权限认证失败'
    ),
    'POLKIT_REGISTERED': EventTypeInfo(
        'PolicyKit注册', '权限', EventLevel.INFO, 'success',
        'PolicyKit认证代理注册'
    ),
    'POLKIT_UNREGISTERED': EventTypeInfo(
        'PolicyKit注销', '权限', EventLevel.INFO, 'success',
        'PolicyKit认证代理注销'
    ),
}

# ==================== 其他系统事件映射 ====================
SYSTEM_EVENTS: Dict[str, EventTypeInfo] = {
    'GKR_PAM': EventTypeInfo(
        'Keyring密码更新失败', '系统', EventLevel.INFO, '',
        'GNOME Keyring密码更新失败'
    ),
    'UNIX_CHKPWD': EventTypeInfo(
        '密码检查', '认证', EventLevel.INFO, '',
        'unix_chkpwd密码检查'
    ),
    'UNIX_CHKPWD_FAILED': EventTypeInfo(
        'unix_chkpwd检查失败', '认证', EventLevel.WARNING, 'failed',
        'unix_chkpwd密码检查失败'
    ),
    'RUNUSER_SESSION_OPENED': EventTypeInfo(
        'runuser会话开启', '会话', EventLevel.INFO, 'success',
        'runuser会话开启'
    ),
    'RUNUSER_SESSION_CLOSED': EventTypeInfo(
        'runuser会话关闭', '会话', EventLevel.INFO, 'success',
        'runuser会话关闭'
    ),
    # 通用系统事件
    'RSYSLOG': EventTypeInfo(
        'Rsyslog消息', '系统', EventLevel.INFO, '',
        'Rsyslog系统日志消息'
    ),
    'AUDITD': EventTypeInfo(
        'Audit守护进程', '系统', EventLevel.INFO, '',
        'Audit守护进程消息'
    ),
    'KERNEL': EventTypeInfo(
        '内核消息', '系统', EventLevel.INFO, '',
        'Linux内核消息'
    ),
    'TIME_SYNC': EventTypeInfo(
        '时间同步', '系统', EventLevel.INFO, '',
        'NTP/Chrony时间同步消息'
    ),
    'SYSTEMD_TMPFILES': EventTypeInfo(
        '临时文件清理', '系统', EventLevel.INFO, '',
        'systemd-tmpfiles临时文件清理'
    ),
    'SECURITY_CHECK': EventTypeInfo(
        '安全检查', '安全', EventLevel.INFO, '',
        'AIDE/RKHunter等安全检查'
    ),
    'IMJOURNAL': EventTypeInfo(
        'Journal日志', '系统', EventLevel.INFO, '',
        'systemd journal日志消息'
    ),
    'SYSTEMD_OTHER': EventTypeInfo(
        'Systemd消息', '系统', EventLevel.INFO, '',
        '其他systemd消息'
    ),
    'SSH_OTHER': EventTypeInfo(
        'SSH其他事件', 'SSH', EventLevel.INFO, '',
        '未分类的SSH事件'
    ),
    'GENERIC': EventTypeInfo(
        '通用消息', '系统', EventLevel.INFO, '',
        '未分类的系统消息'
    ),
    # 通用会话事件
    'GENERIC_SESSION_OPENED': EventTypeInfo(
        '会话开启', '会话', EventLevel.INFO, 'success',
        '通用会话开启事件'
    ),
    'GENERIC_SESSION_CLOSED': EventTypeInfo(
        '会话关闭', '会话', EventLevel.INFO, 'success',
        '通用会话关闭事件'
    ),
    # 防火墙事件
    'UFW_BLOCK': EventTypeInfo(
        'UFW阻止连接', '安全', EventLevel.WARNING, 'denied',
        'UFW防火墙阻止连接'
    ),
    'UFW_ALLOW': EventTypeInfo(
        'UFW允许连接', '安全', EventLevel.INFO, 'success',
        'UFW防火墙允许连接'
    ),
    'IPTABLES_BLOCK': EventTypeInfo(
        'iptables阻止连接', '安全', EventLevel.WARNING, 'denied',
        'iptables防火墙阻止连接'
    ),
    'FIREWALL_BLOCK': EventTypeInfo(
        '防火墙阻止', '安全', EventLevel.WARNING, 'denied',
        '防火墙阻止连接'
    ),
    # PAM认证计数事件
    'PAM_TALLY': EventTypeInfo(
        'PAM认证失败计数', '认证', EventLevel.WARNING, 'failed',
        'PAM认证失败次数统计'
    ),
    'PAM_FAILLOCK': EventTypeInfo(
        'PAM账户锁定', '认证', EventLevel.WARNING, 'failed',
        'PAM faillock账户锁定/解锁'
    ),
}


# ==================== 合并所有事件映射 ====================
ALL_EVENT_TYPES: Dict[str, EventTypeInfo] = {}
ALL_EVENT_TYPES.update(SSH_EVENTS)
ALL_EVENT_TYPES.update(SUDO_EVENTS)
ALL_EVENT_TYPES.update(SU_EVENTS)
ALL_EVENT_TYPES.update(CRON_EVENTS)
ALL_EVENT_TYPES.update(USER_MGMT_EVENTS)
ALL_EVENT_TYPES.update(LOGIN_EVENTS)
ALL_EVENT_TYPES.update(SYSTEMD_EVENTS)
ALL_EVENT_TYPES.update(POLKIT_EVENTS)
ALL_EVENT_TYPES.update(SYSTEM_EVENTS)


def get_event_info(event_type: str) -> Optional[EventTypeInfo]:
    """获取事件类型信息"""
    return ALL_EVENT_TYPES.get(event_type)


def get_event_tuple(event_type: str) -> Tuple[str, str, EventLevel, str]:
    """获取事件类型元组 (兼容旧格式)"""
    info = ALL_EVENT_TYPES.get(event_type)
    if info:
        return (info.name, info.category, info.level, info.result)
    return ('未知事件', '其他', EventLevel.INFO, '')


def get_event_name(event_type: str) -> str:
    """获取事件中文名称"""
    info = ALL_EVENT_TYPES.get(event_type)
    return info.name if info else event_type


def get_event_category(event_type: str) -> str:
    """获取事件分类"""
    info = ALL_EVENT_TYPES.get(event_type)
    return info.category if info else '其他'


def get_event_level(event_type: str) -> EventLevel:
    """获取事件级别"""
    info = ALL_EVENT_TYPES.get(event_type)
    return info.level if info else EventLevel.INFO


# ==================== 事件分类统计 ====================
def get_events_by_category() -> Dict[str, list]:
    """按分类获取所有事件类型"""
    categories = {}
    for event_type, info in ALL_EVENT_TYPES.items():
        if info.category not in categories:
            categories[info.category] = []
        categories[info.category].append({
            'type': event_type,
            'name': info.name,
            'level': info.level.value,
            'description': info.description
        })
    return categories


def get_security_events() -> list:
    """获取所有安全相关事件类型"""
    security_categories = ['认证', '安全', '权限']
    return [
        event_type for event_type, info in ALL_EVENT_TYPES.items()
        if info.category in security_categories or info.level in [EventLevel.WARNING, EventLevel.CRITICAL]
    ]


def get_login_events() -> list:
    """获取所有登录相关事件类型"""
    return [
        event_type for event_type, info in ALL_EVENT_TYPES.items()
        if '登录' in info.name or 'LOGIN' in event_type or 'ACCEPTED' in event_type
    ]


def get_failed_events() -> list:
    """获取所有失败事件类型"""
    return [
        event_type for event_type, info in ALL_EVENT_TYPES.items()
        if info.result == 'failed' or 'FAILED' in event_type or 'FAILURE' in event_type
    ]


# ==================== 通用系统事件映射（补充） ====================
GENERIC_EVENTS: Dict[str, EventTypeInfo] = {
    # Systemd其他事件
    'SYSTEMD_OTHER': EventTypeInfo(
        'Systemd消息', '系统', EventLevel.INFO, '',
        '其他systemd相关消息'
    ),
    'SYSTEMD_TMPFILES': EventTypeInfo(
        '临时文件清理', '系统', EventLevel.INFO, 'success',
        'systemd-tmpfiles清理临时文件'
    ),
    
    # 日志系统事件
    'RSYSLOG': EventTypeInfo(
        'Rsyslog消息', '系统', EventLevel.INFO, '',
        'Rsyslog日志系统消息'
    ),
    'RSYSLOG_START': EventTypeInfo(
        'Rsyslog启动', '系统', EventLevel.INFO, 'success',
        'Rsyslog服务启动'
    ),
    'RSYSLOG_STOP': EventTypeInfo(
        'Rsyslog停止', '系统', EventLevel.INFO, 'success',
        'Rsyslog服务停止'
    ),
    
    # 审计系统事件
    'AUDITD': EventTypeInfo(
        'Audit守护进程', '系统', EventLevel.INFO, '',
        'Audit守护进程消息'
    ),
    'AUDITD_START': EventTypeInfo(
        'Audit启动', '系统', EventLevel.INFO, 'success',
        'Audit服务启动'
    ),
    'AUDITD_STOP': EventTypeInfo(
        'Audit停止', '系统', EventLevel.INFO, 'success',
        'Audit服务停止'
    ),
    
    # 内核事件
    'KERNEL': EventTypeInfo(
        '内核消息', '系统', EventLevel.INFO, '',
        'Linux内核消息'
    ),
    'KERNEL_ERROR': EventTypeInfo(
        '内核错误', '系统', EventLevel.ERROR, '',
        'Linux内核错误消息'
    ),
    'KERNEL_WARNING': EventTypeInfo(
        '内核警告', '系统', EventLevel.WARNING, '',
        'Linux内核警告消息'
    ),
    
    # 时间同步事件
    'TIME_SYNC': EventTypeInfo(
        '时间同步', '系统', EventLevel.INFO, '',
        'NTP/Chrony时间同步消息'
    ),
    'TIME_SYNC_SUCCESS': EventTypeInfo(
        '时间同步成功', '系统', EventLevel.INFO, 'success',
        '时间同步成功'
    ),
    'TIME_SYNC_FAILED': EventTypeInfo(
        '时间同步失败', '系统', EventLevel.WARNING, 'failed',
        '时间同步失败'
    ),
    
    # 网络事件
    'NETWORK_UP': EventTypeInfo(
        '网络接口启动', '网络', EventLevel.INFO, 'success',
        '网络接口启动'
    ),
    'NETWORK_DOWN': EventTypeInfo(
        '网络接口关闭', '网络', EventLevel.INFO, 'success',
        '网络接口关闭'
    ),
    'DHCP_LEASE': EventTypeInfo(
        'DHCP租约', '网络', EventLevel.INFO, 'success',
        'DHCP获取IP地址'
    ),
    
    # 服务管理事件
    'SERVICE_START': EventTypeInfo(
        '服务启动', '系统', EventLevel.INFO, 'success',
        '系统服务启动'
    ),
    'SERVICE_STOP': EventTypeInfo(
        '服务停止', '系统', EventLevel.INFO, 'success',
        '系统服务停止'
    ),
    'SERVICE_RESTART': EventTypeInfo(
        '服务重启', '系统', EventLevel.INFO, 'success',
        '系统服务重启'
    ),
    'SERVICE_FAILED': EventTypeInfo(
        '服务失败', '系统', EventLevel.ERROR, 'failed',
        '系统服务启动失败'
    ),
    
    # SSH其他事件
    'SSH_OTHER': EventTypeInfo(
        'SSH其他事件', 'SSH', EventLevel.INFO, '',
        '未分类的SSH事件'
    ),
    
    # 通用事件
    'GENERIC': EventTypeInfo(
        '通用消息', '其他', EventLevel.INFO, '',
        '未分类的系统消息'
    ),
    'UNKNOWN': EventTypeInfo(
        '未知事件', '其他', EventLevel.INFO, '',
        '无法识别的事件类型'
    ),
}

# ==================== UTMP/WTMP/BTMP 二进制日志事件 ====================
UTMP_EVENTS: Dict[str, EventTypeInfo] = {
    'UTMP_LOGIN': EventTypeInfo(
        '用户登录', '认证', EventLevel.INFO, 'success',
        '用户登录系统'
    ),
    'UTMP_LOGOUT': EventTypeInfo(
        '用户登出', '认证', EventLevel.INFO, 'success',
        '用户登出系统'
    ),
    'UTMP_BOOT': EventTypeInfo(
        '系统启动', '系统', EventLevel.INFO, 'success',
        '系统启动记录'
    ),
    'UTMP_SHUTDOWN': EventTypeInfo(
        '系统关机', '系统', EventLevel.INFO, 'success',
        '系统关机记录'
    ),
    'UTMP_RUNLEVEL': EventTypeInfo(
        '运行级别变更', '系统', EventLevel.INFO, 'success',
        '系统运行级别变更'
    ),
    'BTMP_FAILED_LOGIN': EventTypeInfo(
        '登录失败', '认证', EventLevel.WARNING, 'failed',
        '用户登录失败记录'
    ),
    'WTMP_LOGIN': EventTypeInfo(
        '登录记录', '认证', EventLevel.INFO, 'success',
        'wtmp登录记录'
    ),
    'WTMP_LOGOUT': EventTypeInfo(
        '登出记录', '认证', EventLevel.INFO, 'success',
        'wtmp登出记录'
    ),
    'LASTLOG_ENTRY': EventTypeInfo(
        '最后登录', '认证', EventLevel.INFO, 'success',
        '用户最后登录记录'
    ),
}

# ==================== Audit审计日志事件 ====================
AUDIT_EVENTS: Dict[str, EventTypeInfo] = {
    # 用户认证
    'AUDIT_USER_AUTH': EventTypeInfo(
        '用户认证', '认证', EventLevel.INFO, '',
        '用户认证事件'
    ),
    'AUDIT_USER_ACCT': EventTypeInfo(
        '用户账户', '认证', EventLevel.INFO, '',
        '用户账户事件'
    ),
    'AUDIT_USER_START': EventTypeInfo(
        '用户会话开始', '会话', EventLevel.INFO, 'success',
        '用户会话开始'
    ),
    'AUDIT_USER_END': EventTypeInfo(
        '用户会话结束', '会话', EventLevel.INFO, 'success',
        '用户会话结束'
    ),
    'AUDIT_USER_LOGIN': EventTypeInfo(
        '用户登录', '认证', EventLevel.INFO, 'success',
        '用户登录事件'
    ),
    'AUDIT_USER_LOGOUT': EventTypeInfo(
        '用户登出', '认证', EventLevel.INFO, 'success',
        '用户登出事件'
    ),
    'AUDIT_USER_ERR': EventTypeInfo(
        '用户错误', '认证', EventLevel.WARNING, 'failed',
        '用户操作错误'
    ),
    
    # 系统调用
    'AUDIT_SYSCALL': EventTypeInfo(
        '系统调用', '系统', EventLevel.INFO, '',
        '系统调用审计'
    ),
    'AUDIT_EXECVE': EventTypeInfo(
        '命令执行', '系统', EventLevel.INFO, '',
        '命令执行审计'
    ),
    'AUDIT_PATH': EventTypeInfo(
        '文件路径', '文件', EventLevel.INFO, '',
        '文件路径访问'
    ),
    'AUDIT_CWD': EventTypeInfo(
        '工作目录', '文件', EventLevel.INFO, '',
        '当前工作目录'
    ),
    
    # 文件操作
    'AUDIT_FILE_ACCESS': EventTypeInfo(
        '文件访问', '文件', EventLevel.INFO, '',
        '文件访问审计'
    ),
    'AUDIT_FILE_MODIFY': EventTypeInfo(
        '文件修改', '文件', EventLevel.INFO, '',
        '文件修改审计'
    ),
    'AUDIT_FILE_DELETE': EventTypeInfo(
        '文件删除', '文件', EventLevel.WARNING, '',
        '文件删除审计'
    ),
    
    # 权限变更
    'AUDIT_CHMOD': EventTypeInfo(
        '权限变更', '权限', EventLevel.INFO, '',
        '文件权限变更'
    ),
    'AUDIT_CHOWN': EventTypeInfo(
        '所有者变更', '权限', EventLevel.INFO, '',
        '文件所有者变更'
    ),
    
    # 服务管理
    'AUDIT_SERVICE_START': EventTypeInfo(
        '服务启动', '服务', EventLevel.INFO, 'success',
        '服务启动审计'
    ),
    'AUDIT_SERVICE_STOP': EventTypeInfo(
        '服务停止', '服务', EventLevel.INFO, 'success',
        '服务停止审计'
    ),
    
    # 配置变更
    'AUDIT_CONFIG_CHANGE': EventTypeInfo(
        '配置变更', '配置', EventLevel.INFO, '',
        '系统配置变更'
    ),
    'AUDIT_DAEMON_CONFIG': EventTypeInfo(
        '守护进程配置', '配置', EventLevel.INFO, '',
        '守护进程配置变更'
    ),
    
    # 网络
    'AUDIT_NETFILTER_CFG': EventTypeInfo(
        '防火墙配置', '网络', EventLevel.INFO, '',
        '防火墙规则变更'
    ),
    
    # 其他
    'AUDIT_PROCTITLE': EventTypeInfo(
        '进程标题', '系统', EventLevel.INFO, '',
        '进程命令行'
    ),
    'AUDIT_EOE': EventTypeInfo(
        '事件结束', '系统', EventLevel.INFO, '',
        '审计事件结束标记'
    ),
    'AUDIT_OTHER': EventTypeInfo(
        '其他审计', '系统', EventLevel.INFO, '',
        '其他审计事件'
    ),
}

# 更新 ALL_EVENT_TYPES
ALL_EVENT_TYPES.update(GENERIC_EVENTS)
ALL_EVENT_TYPES.update(UTMP_EVENTS)
ALL_EVENT_TYPES.update(AUDIT_EVENTS)


# ==================== 补充缺失的事件类型 ====================
ADDITIONAL_EVENTS: Dict[str, EventTypeInfo] = {
    'SECURITY_CHECK': EventTypeInfo(
        '安全检查', '安全', EventLevel.INFO, '',
        'AIDE/rkhunter等安全检查'
    ),
    'IMJOURNAL': EventTypeInfo(
        'Journal日志', '系统', EventLevel.INFO, '',
        'systemd journal日志消息'
    ),
}

ALL_EVENT_TYPES.update(ADDITIONAL_EVENTS)
