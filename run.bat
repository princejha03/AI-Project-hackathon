@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel%==0 (
    python run.py full
    goto :done
)

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 run.py full
    goto :done
)

echo Python was not found on PATH. Install Python 3.10+ from https://python.org and try again.
pause
exit /b 1

:done
echo.
pause
endlocal
