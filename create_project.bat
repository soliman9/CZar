@echo off
REM This script creates the directory and file structure for a password manager project.

REM Define the base directory name
set "BASE_DIR=E:\Open-source\MyProjects\CZar"

echo Creating project structure for %BASE_DIR%...

REM Create the base directory
@REM mkdir "%BASE_DIR%"

REM Create top-level files
echo. > "%BASE_DIR%\.gitignore"
echo. > "%BASE_DIR%\pyproject.toml"
echo. > "%BASE_DIR%\README.md"

REM Create the 'config' directory and its content
mkdir "%BASE_DIR%\config"
echo. > "%BASE_DIR%\config\settings.py"

REM Create the 'src' directory and its nested 'pass_man' directory
mkdir "%BASE_DIR%\src"
mkdir "%BASE_DIR%\src\pass_man"

REM Create files inside 'src/pass_man'
echo. > "%BASE_DIR%\src\pass_man\__init__.py"
echo. > "%BASE_DIR%\src\pass_man\main.py"
echo. > "%BASE_DIR%\src\pass_man\cli.py"
echo. > "%BASE_DIR%\src\pass_man\vault.py"
echo. > "%BASE_DIR%\src\pass_man\crypto.py"
echo. > "%BASE_DIR%\src\pass_man\storage.py"

echo Project structure created successfully in .\%BASE_DIR%\
