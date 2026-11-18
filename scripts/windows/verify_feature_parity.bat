@echo off
rem Run from the repository root so relative data/model paths resolve.
cd /d "%~dp0..\.."
rem ---------------------------------------------------------
rem Phase 7: Live Capture Feature Parity Verification
rem Compares live parser features against training pipeline,
rem stress-tests malformed inputs, and generates parity report.
rem ---------------------------------------------------------

set DATA_DIR=data
set OUT_DIR=docs
set PYTHON=venv\Scripts\python.exe

if not exist %PYTHON% (
    set PYTHON=python
)

echo =========================================================
echo Running Phase 7: Feature Parity and Robustness Verification
echo =========================================================

%PYTHON% training\verify_feature_parity.py ^
    --data-dir %DATA_DIR% ^
    --output-dir %OUT_DIR%

echo.
echo Verification finished.
echo Review report in docs\FEATURE_PARITY_LIVE_CAPTURE.md
pause

