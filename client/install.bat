@echo off
chcp 65001 >nul
title SmartProxy Installer

echo.
echo ╔═══════════════════════════════════════════════════════╗
echo ║           SmartProxy - Установка                      ║
echo ╚═══════════════════════════════════════════════════════╝
echo.

:: Проверяем Python
echo [1/4] Проверка Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo ❌ Python не найден!
    echo.
    echo Скачайте Python с https://www.python.org/downloads/
    echo При установке ОБЯЗАТЕЛЬНО отметьте "Add Python to PATH"
    echo.
    echo После установки Python запустите этот файл снова.
    echo.
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo ✓ Python %PYVER% найден

:: Устанавливаем зависимости
echo.
echo [2/4] Установка зависимостей...
pip install PyYAML >nul 2>&1
if errorlevel 1 (
    echo ⚠ Предупреждение: не удалось установить PyYAML
    echo Попробуйте вручную: pip install PyYAML
) else (
    echo ✓ Зависимости установлены
)

:: Создаём ярлык на рабочем столе
echo.
echo [3/4] Создание ярлыка...
set SCRIPT_DIR=%~dp0
set DESKTOP=%USERPROFILE%\Desktop

:: Создаём VBS скрипт для создания ярлыка
echo Set oWS = WScript.CreateObject("WScript.Shell") > "%TEMP%\CreateShortcut.vbs"
echo sLinkFile = "%DESKTOP%\SmartProxy.lnk" >> "%TEMP%\CreateShortcut.vbs"
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> "%TEMP%\CreateShortcut.vbs"
echo oLink.TargetPath = "pythonw.exe" >> "%TEMP%\CreateShortcut.vbs"
echo oLink.Arguments = """%SCRIPT_DIR%smartproxy.py""" >> "%TEMP%\CreateShortcut.vbs"
echo oLink.WorkingDirectory = "%SCRIPT_DIR%" >> "%TEMP%\CreateShortcut.vbs"
echo oLink.Description = "SmartProxy - Умный прокси для обхода блокировок" >> "%TEMP%\CreateShortcut.vbs"
echo oLink.Save >> "%TEMP%\CreateShortcut.vbs"

cscript //nologo "%TEMP%\CreateShortcut.vbs"
del "%TEMP%\CreateShortcut.vbs"

if exist "%DESKTOP%\SmartProxy.lnk" (
    echo ✓ Ярлык создан на рабочем столе
) else (
    echo ⚠ Не удалось создать ярлык
)

:: Готово
echo.
echo [4/4] Установка завершена!
echo.
echo ═══════════════════════════════════════════════════════════
echo.
echo  ✓ SmartProxy установлен!
echo.
echo  Как запустить:
echo    • Дважды кликните на ярлык "SmartProxy" на рабочем столе
echo    • Или запустите start.bat в этой папке
echo.
echo  После запуска:
echo    • Программа автоматически настроит Windows
echo    • Chrome и Edge сразу начнут работать через прокси
echo    • YouTube, ChatGPT, Gemini будут доступны
echo.
echo ═══════════════════════════════════════════════════════════
echo.

:: Спрашиваем, запустить ли сейчас
set /p LAUNCH="Запустить SmartProxy сейчас? (Y/N): "
if /i "%LAUNCH%"=="Y" (
    echo.
    echo Запуск SmartProxy...
    start "" python "%SCRIPT_DIR%smartproxy.py"
)

echo.
pause
