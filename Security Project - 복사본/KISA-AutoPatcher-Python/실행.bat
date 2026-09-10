@echo off
echo ====================================================
echo   KISA AutoPatcher (Python) 실행
echo ====================================================
cd /d "%~dp0"
py -3 main.py
if errorlevel 1 (
    echo.
    echo [오류] 프로그램 실행 실패. Python 3이 설치되어 있는지 확인해주세요.
    pause
)
