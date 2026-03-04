@echo off
REM Build script for Windows
REM Creates a standalone CZar executable for Windows

setlocal enabledelayedexpansion

echo === Building CZar for Windows ===
echo Installing build dependencies...
pip install -r requirements-dev.txt

echo Running tests...
pytest tests/ -v || true

echo Building executable...
pyinstaller --onefile --name CZar startCzar.py

echo Creating distribution archive...
cd dist
powershell -NoProfile -Command "Compress-Archive -Path CZar.exe -DestinationPath CZar-windows-x86_64.zip -Force"
cd ..

echo Build complete!
echo Output: dist/CZar-windows-x86_64.zip
dir dist\CZar-windows-x86_64.zip

endlocal
