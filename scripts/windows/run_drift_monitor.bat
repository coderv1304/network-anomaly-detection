@echo off
rem Run from the repository root so relative data/model paths resolve.
cd /d "%~dp0..\.."
rem ---------------------------------------------------------
rem Phase 6: Time-Ordered Drift Monitoring Experiment
rem Tracks distribution shift (Score PSI and Feature KS-tests)
rem and audits warning delay, missed degradation, and false warnings.
rem ---------------------------------------------------------

set DATA_DIR=data
set OUT_DIR=models
set PYTHON=venv\Scripts\python.exe

if not exist %PYTHON% (
    set PYTHON=python
)

echo =========================================================
echo Running Phase 6: Drift Monitoring Experiment
echo =========================================================

%PYTHON% training\drift_monitor.py ^
    --data-dir %DATA_DIR% ^
    --output-dir %OUT_DIR%

echo.
echo Drift experiment finished.
echo Review results in docs\DRIFT_MONITORING.md
pause

