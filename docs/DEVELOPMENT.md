# 开发指南

## 环境要求

- Python 3.8+
- Node.js 16+ (仅用于前端开发)
- SQLite 3

## 开发环境搭建

### 1. 克隆项目

```bash
git clone <repository-url>
cd linux-log-analyzer-opensource
```

### 2. 安装Python依赖

```bash
pip install -r requirements.txt
```

### 3. 运行开发服务器

```bash
python -m backend.main
```

## 项目结构

```
linux-log-analyzer-opensource/
├── backend/              # 后端Python代码
│   ├── core/            # 核心模块
│   │   ├── audit_statistics.py      # 审计日志统计
│   │   ├── cache_manager.py         # SQLite缓存管理
│   │   ├── event_mappings.py        # 事件类型映射
│   │   ├── host_manager.py          # 多主机管理
│   │   ├── log_event.py             # 事件数据结构
│   │   ├── log_manager.py           # 日志管理器
│   │   ├── log_types.py             # 日志类型定义
│   │   ├── statistics_service.py    # 统计服务
│   │   └── year_resolver.py         # 年份解析
│   ├── parsers/         # 日志解析器
│   │   ├── audit_parser.py          # Audit日志
│   │   ├── base_parser.py           # 基类
│   │   ├── lastlog_parser.py        # Lastlog
│   │   ├── syslog_parser.py         # Syslog格式
│   │   └── utmp_parser.py           # UTMP/WTMP/BTMP
│   ├── api.py           # 业务逻辑API
│   ├── webview_api.py   # PyWebview接口
│   └── main.py          # 主入口
├── frontend/            # 编译后的前端
│   ├── index.html
│   └── FastLinuxLog.exe # Windows可执行文件
├── docs/                # 文档
│   ├── ARCHITECTURE.md
│   ├── CODE_REVIEW_SUMMARY.md
│   └── DEVELOPMENT.md (本文件)
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

## 核心概念

### 1. 日志类型 (LogType)

支持的日志类型:
- `audit` - Linux审计日志
- `secure` - 安全日志 (RHEL/CentOS)
- `auth` - 认证日志 (Debian/Ubuntu)
- `btmp` - 失败登录记录
- `wtmp` - 登录记录
- `lastlog` - 最后登录

### 2. 事件结构 (LogEvent)

统一的事件数据结构,包含:
- 基础字段: 时间、主机、进程、用户
- 网络字段: 来源IP、端口
- 事件字段: 类型、名称、级别、结果
- 扩展字段: 各日志类型特有字段

### 3. 解析器 (Parser)

每种日志类型对应一个解析器:
- 继承自 `BaseParser`
- 实现 `parse_line()` 方法
- 返回 `LogEvent` 对象

### 4. 缓存机制

- 使用SQLite存储解析后的事件
- 每种日志类型一个表
- 支持多主机分区
- 文件级缓存验证

## 开发流程

### 添加新的日志类型

1. **定义日志类型**

```python
# backend/core/log_types.py
class LogType(Enum):
    NEW_TYPE = "new_type"

LOG_TYPE_CONFIGS[LogType.NEW_TYPE] = LogTypeConfig(
    name="新日志类型",
    name_en="New Log Type",
    description="描述",
    category=LogCategory.SYSTEM,
    format="syslog",
    parser="syslog",
    file_patterns=[r'^new_type\.log$'],
    priority=2
)
```

2. **创建解析器** (如果需要新格式)

```python
# backend/parsers/new_parser.py
from .base_parser import BaseParser
from ..core.log_event import LogEvent

class NewParser(BaseParser):
    name = "new"
    supported_types = ["new_type"]
    
    def parse_line(self, line: str, record_id: int = 0) -> Optional[LogEvent]:
        # 解析逻辑
        event = LogEvent(record_id=record_id)
        # ... 填充字段
        return event
```

3. **注册解析器**

```python
# backend/parsers/__init__.py
from .new_parser import NewParser

PARSER_REGISTRY["new"] = NewParser
```

4. **添加事件映射**

```python
# backend/core/event_mappings.py
NEW_EVENTS = {
    'NEW_EVENT_TYPE': EventTypeInfo(
        '事件名称', '分类', EventLevel.INFO, 'success',
        '描述'
    ),
}

ALL_EVENT_TYPES.update(NEW_EVENTS)
```

### 添加新的统计维度

1. **在Service中添加方法**

```python
# backend/core/statistics_service.py
def get_new_statistics(self, cursor, table_name, time_cond, params):
    cursor.execute(f"""
        SELECT field, COUNT(*) as count
        FROM {table_name}
        WHERE {time_cond}
        GROUP BY field
    """, params)
    return [{"field": row[0], "count": row[1]} for row in cursor.fetchall()]
```

2. **在API中暴露**

```python
# backend/webview_api.py
def linux_get_new_stats(self, host_id: str):
    service = StatisticsService(self.api.cache_manager.db_path)
    return service.get_new_statistics(host_id)
```

3. **前端调用**

```typescript
const stats = await window.pywebview.api.linux_get_new_stats(hostId);
```

## 调试技巧

### 1. 启用调试模式

```python
# backend/main.py
webview.start(debug=True)  # 启用开发者工具
```

### 2. 查看解析统计

```python
parser = AuditParser()
parser.parse_file("test.log")
parser.print_parse_report()  # 打印解析报告
```

### 3. 检查缓存

```python
from backend.core.cache_manager import LinuxLogCacheManager

cache = LinuxLogCacheManager()
info = cache.get_cache_info()
print(info)
```

### 4. SQL查询调试

```python
import sqlite3
conn = sqlite3.connect("cache/linux/linux_logs.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM events_audit_xxx LIMIT 10")
for row in cursor.fetchall():
    print(row)
```

## 性能优化

### 1. 批量处理

```python
# 推荐: 批量插入
batch = []
for event in events:
    batch.append(event)
    if len(batch) >= 1000:
        cursor.executemany(sql, batch)
        batch = []

# 不推荐: 逐条插入
for event in events:
    cursor.execute(sql, event)
```

### 2. 索引优化

```python
# 为常用查询字段添加索引
cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_timestamp 
    ON events_table(timestamp_unix)
""")
```

### 3. 连接池

```python
# 使用上下文管理器
with sqlite3.connect(db_path) as conn:
    cursor = conn.cursor()
    # ... 操作
    conn.commit()
# 自动关闭连接
```

## 测试

### 单元测试

```bash
python -m pytest tests/
```

### 集成测试

```bash
python -m pytest tests/integration/
```

### 性能测试

```bash
python -m pytest tests/performance/ --benchmark
```

## 代码规范

### Python代码风格

- 遵循 PEP 8
- 使用类型注解
- 文档字符串使用Google风格

### 提交规范

```
feat: 添加新功能
fix: 修复bug
docs: 文档更新
style: 代码格式调整
refactor: 重构
test: 测试相关
chore: 构建/工具相关
```

## 常见问题

### Q: 如何处理大文件?

A: 使用生成器模式逐行处理,避免一次性加载到内存。

### Q: 如何提高解析速度?

A: 
1. 使用批量插入
2. 启用WAL模式
3. 考虑多进程并行

### Q: 如何调试前端?

A: 在main.py中设置 `debug=True` 启用开发者工具。

### Q: 如何添加新的事件类型?

A: 在event_mappings.py中添加映射,无需修改解析器。

## 贡献指南

1. Fork项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启Pull Request

## 联系方式

- Issue: <repository-url>/issues
- Email: <maintainer-email>
