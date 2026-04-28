# 快速开始指南

## 运行项目

### 方法1: 使用Python直接运行

```bash
# 1. 安装依赖
pip install pywebview

# 2. 运行测试
python test_import.py

# 3. 启动应用
python run.py
```

### 方法2: 使用批处理脚本 (Windows)

```bash
# 直接双击运行
run.bat
```

## 编译可执行文件

### Windows平台

```bash
# 方法1: 使用批处理脚本
build.bat

# 方法2: 手动编译
pip install pyinstaller
pyinstaller build.spec --clean --noconfirm
```

编译完成后,可执行文件位于: `dist/LinuxLogAnalyzer.exe`

### Linux平台

```bash
# 1. 安装依赖
pip install pywebview pyinstaller

# 2. 编译
pyinstaller build.spec --clean --noconfirm
```

## 测试导入

运行测试脚本检查所有模块是否正常:

```bash
python test_import.py
```

预期输出:
```
Testing imports...
1. Testing backend package...
   ✓ backend version: 1.0.0
2. Testing core modules...
   ✓ core modules imported
3. Testing parsers...
   ✓ parsers imported
4. Testing API...
   ✓ API imported
5. Testing WebView API...
   ✓ WebView API imported

✅ All imports successful!

Creating API instance...
   ✓ API instance created
   Base dir: .../logs

🎉 Test completed successfully!
```

## 常见问题

### Q: 提示找不到模块?

A: 确保在项目根目录运行,或者设置PYTHONPATH:
```bash
set PYTHONPATH=%CD%
python run.py
```

### Q: PyWebview启动失败?

A: 
1. Windows: 确保安装了Edge WebView2
2. Linux: 安装GTK依赖 `sudo apt install python3-gi gir1.2-webkit2-4.0`
3. macOS: 使用系统自带的WebKit

### Q: 编译后的exe无法运行?

A: 
1. 检查是否有杀毒软件拦截
2. 确保frontend目录被正确打包
3. 查看build.spec中的datas配置

## 开发模式

启用开发者工具:

```python
# 修改 backend/main.py
webview.start(debug=True)  # 启用调试模式
```

## 下一步

- 查看 [开发指南](DEVELOPMENT.md)
- 阅读 [架构文档](ARCHITECTURE.md)
- 了解 [API文档](API.md)
