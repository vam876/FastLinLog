@echo off
REM Run script for Linux Log Analyzer
REM Open Source Edition

echo ========================================
echo Linux Log Analyzer - Starting...
echo ========================================
echo.

python run.py

if errorlevel 1 (
    echo.
    echo Error: Failed to start!
    pause
)
