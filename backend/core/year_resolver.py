#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
智能年份解析器
多级提取和手动选择机制
"""

import os
import re
from datetime import datetime
from typing import Optional, Dict, List, Tuple


class YearResolver:
    """智能年份解析器"""
    
    # 优先级: content > filename > mtime > manual > inferred
    PRIORITY = ['content', 'filename', 'mtime', 'inferred']
    
    # 文件名中的年份模式 - 支持多种格式
    FILENAME_PATTERNS = [
        (r'(\d{4})(\d{2})(\d{2})', 'YYYYMMDD'),           # 20231201
        (r'(\d{4})-(\d{2})-(\d{2})', 'YYYY-MM-DD'),       # 2023-12-01
        (r'(\d{4})年(\d{1,2})月?(\d{1,2})日?', 'CN'),     # 2023年12月01日 或 2023年12日01日
        (r'(\d{4}):(\d{1,2}):(\d{1,2})', 'COLON'),        # 2023:12:1:12:12
        (r'\.(\d{4})$', 'YYYY'),                           # .2023
        (r'_(\d{4})_', 'YYYY'),                            # _2023_
        (r'-(\d{4})$', 'YYYY'),                            # -2023
        (r'-(\d{4})-', 'YYYY'),                            # -2023-
        (r'(\d{4})-\d{1,2}', 'YYYY-MM'),                  # 2023-12
    ]
    
    # 内容中的日期模式
    CONTENT_PATTERNS = [
        # audit日志: msg=audit(1669654278.298:11850296)
        (r'msg=audit\((\d{10,})', 'epoch'),
        # ISO格式: 2023-12-01T12:00:00
        (r'(\d{4})-(\d{2})-(\d{2})T', 'ISO'),
        # 标准日期: 2023-12-01 或 2023/12/01
        (r'(\d{4})[-/](\d{2})[-/](\d{2})', 'date'),
        # 美式日期: 12/01/2023
        (r'(\d{2})/(\d{2})/(\d{4})', 'US_date'),
    ]
    
    def __init__(self):
        self._cache = {}  # 缓存已解析的年份
        self._manual_years = {}  # 手动设置的年份 {file_path: year}
    
    def resolve_year(self, file_path: str, manual_year: int = None) -> Dict:
        """
        多级年份解析
        
        优先级:
        1. 内容提取 (content) - 最可靠
        2. 文件名提取 (filename) - 较可靠
        3. 文件修改时间 (mtime) - 谨慎使用
        4. 智能推断 (inferred) - 最后手段
        
        手动选择可以覆盖任何自动检测结果
        
        Returns:
            {
                "year": 2023,
                "source": "content",
                "confidence": 0.95,
                "all_sources": {"content": 2023, "filename": 2023, "mtime": 2024},
                "date_info": "从日志内容epoch时间戳提取"
            }
        """
        result = {
            "year": None,
            "source": None,
            "confidence": 0,
            "all_sources": {},
            "date_info": ""
        }
        
        # Check cache
        cache_key = f"{file_path}_{manual_year}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # 1. 手动指定 - 最高优先级（包括之前设置的）
        effective_manual_year = manual_year or self._manual_years.get(file_path)
        if effective_manual_year and 2000 <= effective_manual_year <= 2100:
            result["year"] = effective_manual_year
            result["source"] = "manual"
            result["confidence"] = 1.0
            result["date_info"] = "用户手动指定"
            self._cache[cache_key] = result
            return result
        
        # 2. 从内容提取 - 最可靠
        content_year, content_info = self._detect_from_content(file_path)
        if content_year:
            result["all_sources"]["content"] = content_year
            result["year"] = content_year
            result["source"] = "content"
            result["confidence"] = 0.95
            result["date_info"] = content_info
        
        # 3. 从文件名提取
        filename_year, filename_info = self._detect_from_filename(file_path)
        if filename_year:
            result["all_sources"]["filename"] = filename_year
            if not result["year"]:
                result["year"] = filename_year
                result["source"] = "filename"
                result["confidence"] = 0.85
                result["date_info"] = filename_info
        
        # 4. 从文件修改时间 - 谨慎
        mtime_year = self._detect_from_mtime(file_path)
        if mtime_year:
            result["all_sources"]["mtime"] = mtime_year
            if not result["year"]:
                result["year"] = mtime_year
                result["source"] = "mtime"
                result["confidence"] = 0.6
                result["date_info"] = "从文件修改时间推断（可能不准确）"
        
        # 5. 智能推断 - 最后手段
        if not result["year"]:
            result["year"] = datetime.now().year
            result["source"] = "inferred"
            result["confidence"] = 0.3
            result["date_info"] = "使用当前年份（建议手动确认）"
            result["all_sources"]["inferred"] = result["year"]
        
        self._cache[cache_key] = result
        return result
    
    def _detect_from_content(self, file_path: str) -> Tuple[Optional[int], str]:
        """从文件内容提取年份"""
        try:
            # 读取前100行
            with open(file_path, 'rb') as f:
                # 先检查是否是二进制文件
                header = f.read(1024)
                if b'\x00' in header[:100]:
                    # 二进制文件，尝试解析utmp/wtmp格式
                    return self._detect_from_binary(file_path)
                
                f.seek(0)
                lines = []
                for i, line in enumerate(f):
                    if i >= 100:
                        break
                    try:
                        lines.append(line.decode('utf-8', errors='ignore'))
                    except:
                        pass
            
            content = '\n'.join(lines)
            
            # 检查audit日志的epoch时间戳
            epoch_match = re.search(r'msg=audit\((\d{10,})', content)
            if epoch_match:
                epoch = int(epoch_match.group(1)[:10])  # 取前10位
                year = datetime.fromtimestamp(epoch).year
                return year, f"从audit日志epoch时间戳提取 ({epoch})"
            
            # 检查ISO格式日期
            iso_match = re.search(r'(\d{4})-(\d{2})-(\d{2})T', content)
            if iso_match:
                year = int(iso_match.group(1))
                if 2000 <= year <= 2100:
                    return year, f"从ISO日期格式提取 ({iso_match.group(0)})"
            
            # 检查标准日期格式
            date_match = re.search(r'(\d{4})[-/](\d{2})[-/](\d{2})', content)
            if date_match:
                year = int(date_match.group(1))
                if 2000 <= year <= 2100:
                    return year, f"从日期格式提取 ({date_match.group(0)})"
            
            return None, ""
            
        except Exception as e:
            return None, f"读取失败: {e}"
    
    def _detect_from_binary(self, file_path: str) -> Tuple[Optional[int], str]:
        """从二进制文件（utmp/wtmp/btmp）提取年份"""
        try:
            import struct
            
            with open(file_path, 'rb') as f:
                # utmp结构大小通常是384字节
                record = f.read(384)
                if len(record) >= 384:
                    # ut_tv.tv_sec 在偏移量340处（4字节）
                    try:
                        timestamp = struct.unpack('<I', record[340:344])[0]
                        if timestamp > 0:
                            year = datetime.fromtimestamp(timestamp).year
                            if 2000 <= year <= 2100:
                                return year, f"从二进制日志时间戳提取"
                    except:
                        pass
            
            return None, ""
        except:
            return None, ""
    
    def _detect_from_filename(self, file_path: str) -> Tuple[Optional[int], str]:
        """从文件名提取年份"""
        filename = os.path.basename(file_path)
        
        for pattern, format_name in self.FILENAME_PATTERNS:
            match = re.search(pattern, filename)
            if match:
                try:
                    if format_name in ['YYYYMMDD', 'YYYY-MM-DD', 'CN', 'COLON']:
                        year = int(match.group(1))
                    elif format_name in ['YYYY', 'YYYY-MM']:
                        year = int(match.group(1))
                    else:
                        continue
                    
                    if 2000 <= year <= 2100:
                        return year, f"从文件名提取 ({match.group(0)})"
                except:
                    pass
        
        return None, ""
    
    def _detect_from_mtime(self, file_path: str) -> Optional[int]:
        """从文件修改时间推断年份"""
        try:
            mtime = os.path.getmtime(file_path)
            return datetime.fromtimestamp(mtime).year
        except:
            return None
    
    def get_year_suggestion(self, file_path: str) -> Dict:
        """获取年份建议（供前端使用）"""
        result = self.resolve_year(file_path)
        
        # 生成可选年份列表
        current_year = datetime.now().year
        alternatives = list(range(current_year - 5, current_year + 2))
        
        # 将检测到的年份放在首位
        if result["year"] in alternatives:
            alternatives.remove(result["year"])
        alternatives.insert(0, result["year"])
        
        return {
            "suggested_year": result["year"],
            "source": result["source"],
            "confidence": result["confidence"],
            "date_info": result["date_info"],
            "all_sources": result["all_sources"],
            "alternatives": alternatives
        }
    
    def clear_cache(self):
        """清除缓存"""
        self._cache.clear()
    
    def set_manual_year(self, file_path: str, year: int):
        """设置文件的手动年份"""
        print(f"[YearResolver] set_manual_year: {file_path} -> {year}")
        if 2000 <= year <= 2100:
            self._manual_years[file_path] = year
            # 清除该文件的所有缓存（包括带和不带manual_year参数的）
            keys_to_remove = [k for k in list(self._cache.keys()) if k.startswith(file_path)]
            for k in keys_to_remove:
                del self._cache[k]
            print(f"[YearResolver] 已设置手动年份，清除了 {len(keys_to_remove)} 个缓存项")
            print(f"[YearResolver] 当前手动年份: {self._manual_years}")
            return True
        return False
    
    def get_manual_year(self, file_path: str) -> Optional[int]:
        """获取文件的手动年份"""
        return self._manual_years.get(file_path)


# 全局实例
year_resolver = YearResolver()
