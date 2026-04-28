# 架构设计文档

## 系统架构

### 整体架构

```
┌─────────────────────────────────────────┐
│           Frontend (React)              │
│  ┌──────────┐  ┌──────────┐            │
│  │Dashboard │  │LogViewer │            │
│  └──────────┘  └──────────┘            │
└─────────────────────────────────────────┘
                   ↕ PyWebview API
┌─────────────────────────────────────────┐
│          Backend (Python)               │
│  ┌──────────────────────────────────┐  │
│  │      WebView API Layer           │  │
│  └──────────────────────────────────┘  │
│  ┌──────────────────────────────────┐  │
│  │      Business Logic Layer        │  │
│  │  - LinuxLogAPI                   │  │
│  │  - StatisticsService             │  │
│  │  - AuditStatisticsService        │  │
│  └──────────────────────────────────┘  │
│  ┌──────────────────────────────────┐  │
│  │      Data Access Layer           │  │
│  │  - CacheManager (SQLite)         │  │
│  │  - HostManager                   │  │
│  │  - LogManager                    │  │
│  └──────────────────────────────────┘  │
│  ┌──────────────────────────────────┐  │
│  │      Parser Layer                │  │
│  │  - AuditParser                   │  │
│  │  - SyslogParser                  │  │
│  │  - UtmpParser                    │  │
│  │  - LastlogParser                 │  │
│  └──────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

## 核心模块

### 1. 解析器模块 (parsers/)

#### BaseParser
- 所有解析器的基类
- 定义统一的解析接口
- 提供文件读取和编码处理

#### AuditParser
- 解析Linux audit日志
- 支持复杂的msg字段解析
- 十六进制解码
- CRYPTO和SERVICE字段专用处理

#### SyslogParser
- 解析syslog格式日志 (secure, auth, messages等)
- SSH事件识别
- Sudo/Su事件处理
- 系统事件分类

#### UtmpParser
- 解析二进制utmp/wtmp/btmp日志
- 结构体解析
- 登录记录处理

#### LastlogParser
- 解析lastlog二进制日志
- 用户最后登录信息

### 2. 核心模块 (core/)

#### LogEvent
- 统一的日志事件数据结构
- 支持所有日志类型的字段
- 时间戳标准化处理

#### LogManager
- 日志文件扫描和识别
- 文件分组聚合
- 解析器调度

#### HostManager
- 多主机日志管理
- 支持IP命名和备注
- 目录结构识别

#### CacheManager
- SQLite缓存管理
- 批量插入优化
- 导入历史跟踪
- 数据一致性验证

#### StatisticsService
- 统一的统计服务
- 安全日志统计
- 多表聚合查询
- 时间范围过滤

#### AuditStatisticsService
- 审计日志专用统计
- 认证/登录/会话统计
- Top N查询
- 事件分布分析

#### YearResolver
- 智能年份解析
- 多级检测机制
- 手动年份设置

#### EventMappings
- 事件类型映射配置
- 中文名称定义
- 事件分类和级别

### 3. API层

#### LinuxLogAPI
- 业务逻辑封装
- 主机管理
- 事件加载
- 统计查询
- 缓存管理

#### LinuxLogWebAPI
- PyWebview接口适配
- 前端调用桥接
- 进度跟踪
- 文件对话框

## 数据流

### 日志导入流程

```
1. 文件扫描
   HostManager.scan() → 识别主机和日志类型

2. 类型检测
   detect_log_type() → 根据文件名识别类型

3. 解析
   Parser.parse_file() → 逐行解析生成LogEvent

4. 缓存
   CacheManager.cache_events() → 批量写入SQLite

5. 统计
   StatisticsService → 聚合查询生成统计数据
```

### 查询流程

```
1. 前端请求
   React Component → pywebview.api.method()

2. API层
   WebAPI → LinuxLogAPI → Service

3. 数据层
   CacheManager.load_events() → SQLite查询

4. 返回
   LogEvent[] → JSON → React State
```

## 性能优化

### 1. 批量处理
- 1000条/批次插入
- 事务提交优化

### 2. 索引策略
- timestamp_unix索引
- event_type索引
- user/ip索引

### 3. 缓存机制
- 文件级缓存验证
- mtime+size检查
- 增量更新

### 4. 分页查询
- LIMIT/OFFSET
- 前端虚拟滚动

## 扩展性设计

### 添加新日志类型

1. 在LogType枚举中添加类型
2. 创建对应的Parser类
3. 在LOG_TYPE_CONFIGS中配置
4. 更新EventMappings

### 添加新统计维度

1. 在StatisticsService中添加查询方法
2. 在WebAPI中暴露接口
3. 前端调用展示

## 安全考虑

- SQL注入防护: 参数化查询
- 路径遍历防护: 路径验证
- 内存限制: 批量处理
- 错误处理: 异常捕获和日志
