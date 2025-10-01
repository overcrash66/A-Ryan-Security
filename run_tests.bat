@echo off
echo Running all unit tests...

set CURRENT_DIR=%CD%
echo ***** Current directory: %CURRENT_DIR% *****

rem Add the current directory to PYTHONPATH
set PYTHONPATH=%CURRENT_DIR%

rem Set test environment variables
set TESTING=1
set SQLALCHEMY_DATABASE_URI=sqlite:///:memory:
set FLASK_ENV=testing

rem Activate Python virtual environment
call venv\Scripts\activate.bat

rem Run tests from the root directory
cd %CURRENT_DIR%
python -m pytest -v --disable-warnings
pause
