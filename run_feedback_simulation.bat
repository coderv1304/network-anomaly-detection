@echo off
rem ---------------------------------------------------------
rem Phase 5: Time-Ordered Analyst Feedback Simulation
rem Compares No-Feedback Baseline, Random Selection, Top-Alert
rem SOC Triage, and Uncertainty Sampling under fixed budgets.
rem ---------------------------------------------------------

set DATA_DIR=data
set OUT_DIR=models
set PYTHON=venv\Scripts\python.exe

if not exist %PYTHON% (
    set PYTHON=python
)

echo =========================================================
echo Running Phase 5: Simulated Analyst Feedback Experiment
echo =========================================================

%PYTHON% training\simulate_feedback.py ^
    --data-dir %DATA_DIR% ^
    --output-dir %OUT_DIR% ^
    --seeds 42 43 44 45 46 ^
    --budgets 50 100 250 ^
    --model rf

echo.
echo Simulation finished.
echo Review results in docs\FEEDBACK_SIMULATION.md
pause

