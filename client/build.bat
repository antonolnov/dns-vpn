@echo off
echo ========================================
echo   SmartProxy Builder
echo ========================================
echo.

REM Проверяем наличие Python
python --version >nul 2>&1
if errorlevel 1 (
    echo Python не найден! Установите Python 3.8+ с python.org
    pause
    exit /b 1
)

echo Устанавливаем зависимости...
pip install -r requirements.txt

echo.
echo Собираем SmartProxy.exe...
pyinstaller --onefile --console --name SmartProxy --icon=icon.ico smartproxy.py 2>nul || pyinstaller --onefile --console --name SmartProxy smartproxy.py

echo.
echo ========================================

if exist "dist\SmartProxy.exe" (
    echo Сборка успешна!
    echo.
    echo Файлы:
    echo   dist\SmartProxy.exe - основная программа
    echo.
    echo Не забудьте скопировать config.yaml в папку dist!
    copy config.yaml dist\config.yaml >nul
    echo config.yaml скопирован в dist\
) else (
    echo Ошибка сборки!
)

echo ========================================
pause
