@echo off
REM Nexus launcher - starts the REPL (or a one-shot command) with the project venv.
REM Usage:  Nexus            (interactive shell)
REM         Nexus <cmd> ...  (one-shot)
"%~dp0.venv\Scripts\python.exe" "%~dp0main.py" %*
