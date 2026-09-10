@echo off
echo ====================================================
echo   KISA AutoPatcher (Python) - 의존 패키지 설치
echo ====================================================
py -3 -m pip install openpyxl pyautogui pillow uiautomation --quiet
echo.
echo [완료] 패키지 설치가 완료되었습니다.
pause
