@echo off
rem ---------------------------------------------------------
rem Run the three baselines (RF, LR, IsolationForest) over
rem seeds 42 43 44 45 46 using the day‑based split.
rem ---------------------------------------------------------

set DATA_DIR=data
set OUT_DIR=models
set SPLIT=day_based

rem ---- Random Forest (multiclass) ----
for %%S in (42 43 44 45 46) do (
    echo ==== Random Forest seed %%S ====
    python training/train_pipeline.py ^
        --data-dir %DATA_DIR% ^
        --output-dir %OUT_DIR% ^
        --split-mode %SPLIT% ^
        --model rf ^
        --seed %%S ^
        --task multiclass
)

rem ---- Logistic Regression (multiclass) ----
for %%S in (42 43 44 45 46) do (
    echo ==== Logistic Regression seed %%S ====
    python training/train_pipeline.py ^
        --data-dir %DATA_DIR% ^
        --output-dir %OUT_DIR% ^
        --split-mode %SPLIT% ^
        --model lr ^
        --seed %%S ^
        --task multiclass
)

rem ---- IsolationForest (binary attack) ----
for %%S in (42 43 44 45 46) do (
    echo ==== IsolationForest seed %%S ====
    python training/isolation_forest.py ^
        --data-dir %DATA_DIR% ^
        --output-dir %OUT_DIR% ^
        --seed %%S
)

echo All runs finished.
pause

