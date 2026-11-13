@echo off
rem ---------------------------------------------------------
rem Run only the IsolationForest baseline over seeds 42-46.
rem ---------------------------------------------------------

set DATA_DIR=data
set OUT_DIR=models
set PYTHON=venv\Scripts\python.exe

if not exist %PYTHON% (
    set PYTHON=python
)

rem ---- IsolationForest (binary attack) ----
for %%S in (42 43 44 45 46) do (
    echo ==== IsolationForest seed %%S ====
    %PYTHON% training\isolation_forest.py --data-dir %DATA_DIR% --output-dir %OUT_DIR% --seed %%S
)

echo.
echo IsolationForest runs finished.
pause
