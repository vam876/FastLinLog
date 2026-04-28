#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Linux Log Analyzer - Run Script
Open Source Edition
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == '__main__':
    from backend.main import main
    main()
