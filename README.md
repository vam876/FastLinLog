# Linux Log Analyzer

一个强大的Linux日志分析工具,支持多种日志格式的解析、分析和可视化。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Status: Beta](https://img.shields.io/badge/status-beta-orange.svg)]()

## ✨ 功能特性

- 🔍 **多格式支持** - audit, secure, auth, btmp, wtmp, lastlog
- 🏠 **多主机管理** - 自动识别和管理多主机日志
- ⚡ **智能缓存** - SQLite缓存加速,批量处理优化
- 📊 **实时统计** - 登录统计、安全分析、事件分布
- 🎯 **智能解析** - 自动年份识别、事件分类、字段提取
- 🖥️ **桌面应用** - 基于PyWebview的跨平台桌面应用

## 🚀 快速开始

### 安装依赖

```bash
pip install pywebview
```

### 运行程序

```bash
# 方法1: Python脚本
python run.py

# 方法2: 批处理 (Windows)
run.bat

# 方法3: 测试导入
python test_import.py
```

### 编译可执行文件

```bash
# 安装编译工具
pip install pyinstaller

# 编译
build.bat
# 或
pyinstaller build.spec --clean --noconfirm

# 运行
dist\LinuxLogAnalyzer.exe
```

## 📖 文档

- [快速开始](docs/QUICK_START.md) - 5分钟上手指南
- [开发指南](docs/DEVELOPMENT.md) - 开发环境搭建和API说明
- [架构设计](docs/ARCHITECTURE.md) - 系统架构和设计思路
- [代码审查](docs/CODE_REVIEW_SUMMARY.md) - 代码质量评估
- [更新日志](CHANGELOG.md) - 版本更新记录

## 🏗️ 技术栈

### 后端
- Python 3.8+
- SQLite3 (数据缓存)
- PyWebview (桌面应用框架)

### 前端  
- React 18
- TypeScript
- Vite

## 📁 项目结构

```
linux-log-analyzer-opensource/
├── backend/              # 后端Python代码
│   ├── core/            # 核心模块
│   │   ├── audit_statistics.py      # 审计日志统计
│   │   ├── cache_manager.py         # SQLite缓存
│   │   ├── event_mappings.py        # 事件映射
│   │   ├── host_manager.py          # 主机管理
│   │   ├── log_event.py             # 事件结构
│   │   ├── log_manager.py           # 日志管理
│   │   ├── log_types.py             # 类型定义
│   │   ├── statistics_service.py    # 统计服务
│   │   └── year_resolver.py         # 年份解析
│   ├── parsers/         # 日志解析器
│   │   ├── audit_parser.py          # Audit日志
│   │   ├── syslog_parser.py         # Syslog格式
│   │   ├── utmp_parser.py           # UTMP/WTMP/BTMP
│   │   └── lastlog_parser.py        # Lastlog
│   ├── api.py           # 业务逻辑API
│   ├── webview_api.py   # PyWebview接口
│   └── main.py          # 主入口
├── frontend/            # 编译后的前端
├── docs/                # 文档
├── run.py               # 运行脚本
├── build.spec           # 编译配置
└── test_import.py       # 测试脚本
```

## 🧪 测试

```bash
# 导入测试
python test_import.py

# 预期输出
✓ backend version: 1.0.0
✓ core modules imported
✓ parsers imported
✓ API imported
✓ WebView API imported
✅ All imports successful!
```

## 📊 支持的日志类型

| 日志类型 | 格式 | 说明 |
|---------|------|------|
| audit | 文本 | Linux审计日志 |
| secure | syslog | 安全日志(RHEL/CentOS) |
| auth | syslog | 认证日志(Debian/Ubuntu) |
| btmp | 二进制 | 失败登录记录 |
| wtmp | 二进制 | 登录记录 |
| lastlog | 二进制 | 最后登录 |

## 🎯 核心功能

### 日志解析
- ✅ 自动识别日志类型
- ✅ 智能年份推断
- ✅ 批量处理优化
- ✅ 错误统计和报告

### 统计分析
- ✅ 登录成功/失败统计
- ✅ Top失败IP/用户
- ✅ 时间趋势分析
- ✅ 事件类型分布

### 多主机管理
- ✅ 自动识别主机IP
- ✅ 支持中文备注
- ✅ 目录结构自适应
- ✅ 文件聚合管理

## 🔧 开发

### 环境要求
- Python 3.8+
- pip

### 开发模式

```bash
# 克隆项目
git clone <repository-url>
cd linux-log-analyzer-opensource

# 安装依赖
pip install -r requirements.txt

# 运行
python run.py
```

### 添加新日志类型

1. 在 `backend/core/log_types.py` 定义类型
2. 创建解析器 `backend/parsers/new_parser.py`
3. 注册解析器 `backend/parsers/__init__.py`
4. 添加事件映射 `backend/core/event_mappings.py`

详见 [开发指南](docs/DEVELOPMENT.md)

## 🤝 贡献

欢迎提交 Issue 和 Pull Request!

### 贡献流程
1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

感谢所有为本项目做出贡献的开发者!

## 📞 联系方式

- Issues: [GitHub Issues](https://github.com/your-repo/issues)
- Email: your-email@example.com
- 文档: [在线文档](https://your-docs-url)

## 🌟 Star History

如果这个项目对你有帮助,请给个 Star ⭐

---

**Made with ❤️ by the Linux Log Analyzer Team**
