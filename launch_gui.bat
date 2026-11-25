@echo off
cd /d "%~dp0"
if exist "C:\Users\bannei\AppData\Local\Programs\Python\Python313\python.exe" (
    "C:\Users\bannei\AppData\Local\Programs\Python\Python313\python.exe" main.py %*
) else (
    python main.py %*
)
