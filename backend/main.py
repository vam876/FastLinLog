#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Linux日志分析工具 - 主入口
"""

import os
import sys
import mimetypes
import webview

# 添加项目根目录到路径
if getattr(sys, 'frozen', False):
    # PyInstaller 打包后的路径
    BASE_DIR = sys._MEIPASS  # 临时解压目录
    APP_DIR = os.path.dirname(sys.executable)  # exe 所在目录
else:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    APP_DIR = BASE_DIR

sys.path.insert(0, BASE_DIR)

# 确保正确的MIME类型
mimetypes.init()
mimetypes.add_type('application/javascript', '.js')
mimetypes.add_type('application/javascript', '.mjs')
mimetypes.add_type('text/css', '.css')


def get_entrypoint():
    """获取入口文件路径"""
    # 打包后优先使用 _MEIPASS 中的 gui 目录
    if getattr(sys, 'frozen', False):
        gui_path = os.path.join(sys._MEIPASS, 'gui', 'index.html')
        if os.path.exists(gui_path):
            return gui_path
    
    # 开发模式：优先使用构建后的 frontend 目录 (opensource version)
    frontend_path = os.path.join(BASE_DIR, 'frontend', 'index.html')
    if os.path.exists(frontend_path):
        return frontend_path
    
    # 开发模式：使用构建后的 gui 目录
    gui_path = os.path.join(BASE_DIR, 'gui', 'index.html')
    if os.path.exists(gui_path):
        return gui_path
    
    # 开发模式使用根目录的 index.html
    index_path = os.path.join(BASE_DIR, 'index.html')
    if os.path.exists(index_path):
        return index_path
    
    return frontend_path


def main():
    from backend.webview_api import LinuxLogWebAPI
    
    api = LinuxLogWebAPI()
    entry = get_entrypoint()
    
    print(f"[Linux Log Analyzer] 启动中...")
    print(f"[Linux Log Analyzer] BASE_DIR: {BASE_DIR}")
    print(f"[Linux Log Analyzer] 入口文件: {entry}")
    print(f"[Linux Log Analyzer] 文件存在: {os.path.exists(entry)}")
    
    # 检查是否使用开发服务器
    use_dev = os.environ.get('PYWEBVIEW_USE_DEV_SERVER', '0') == '1'
    if use_dev:
        url = 'http://localhost:3000'
        print(f"[Linux Log Analyzer] 使用开发服务器: {url}")
    else:
        # 使用本地文件，确保路径正确
        if os.path.exists(entry):
            url = entry
        else:
            print(f"[Linux Log Analyzer] 错误: 入口文件不存在: {entry}")
            # 列出可能的目录内容
            parent_dir = os.path.dirname(entry)
            if os.path.exists(parent_dir):
                print(f"[Linux Log Analyzer] {parent_dir} 目录内容: {os.listdir(parent_dir)}")
            else:
                print(f"[Linux Log Analyzer] 目录不存在: {parent_dir}")
            return
    
    window = webview.create_window(
        'FastLinLog v1.0.0',
        url,
        js_api=api,
        width=1400,
        height=900,
        resizable=True,
        background_color='#1e1e1e',
        text_select=True
    )
    
    webview.start(debug=False)


if __name__ == '__main__':
    main()
