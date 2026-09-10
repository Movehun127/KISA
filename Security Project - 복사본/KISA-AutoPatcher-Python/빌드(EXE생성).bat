@echo off
echo ====================================================
echo   KISA AutoPatcher - 단일 EXE 빌드
echo ====================================================
cd /d "%~dp0"

py -3 -m PyInstaller ^
    --onefile ^
    --windowed ^
    --name "KISA-AutoPatcher" ^
    --add-data "config;config" ^
    --add-data "core;core" ^
    --hidden-import "core.detector" ^
    --hidden-import "core.remediator" ^
    --hidden-import "core.reporter" ^
    --hidden-import "core.capturer" ^
    --hidden-import "uiautomation" ^
    --hidden-import "pyautogui" ^
    --hidden-import "openpyxl" ^
    --hidden-import "PIL" ^
    --hidden-import "winreg" ^
    main.py

if errorlevel 1 (
    echo.
    echo [오류] 빌드 실패. 위 오류 메시지를 확인해주세요.
    pause
    exit /b 1
)

:: config 폴더를 dist 내부로 자동 복사
echo.
echo [안내] config 폴더를 dist 내부로 자동 복사 중...
powershell -Command "Copy-Item -Recurse -Force 'config' 'dist\config'"

echo.
echo ====================================================
echo  [완료] dist\ 폴더에 모든 파일이 빌드 및 복사되었습니다.
echo  이제 dist\ 폴더의 내용물만 그대로 배포하시면 됩니다.
echo ====================================================
pause
