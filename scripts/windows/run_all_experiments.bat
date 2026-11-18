@echo off
rem Run from the repository root so relative data/model paths resolve.
cd /d "%~dp0..\.."
REM =========================================================
REM  NetShield Research Workbench — Full Experiment Runner
REM  Phases 3-7 (Baselines, Alert Burden, Feedback,
REM             Drift Monitoring, Feature Parity)
REM
REM  Usage: .\run_all_experiments.bat
REM  Prerequisite: venv activated in this shell, or run from
REM  within the activated environment.
REM
REM  Estimated wall-clock time: 90-120 minutes
REM  (Baseline training is the dominant cost)
REM =========================================================

echo.
echo =========================================================
echo   NetShield Research Workbench - Full Experiment Suite
echo =========================================================
echo.
echo Dataset   : CIC-IDS-2017 (day-based temporal split)
echo Seeds     : 42 43 44 45 46
echo Phases    : 3 (Baselines) + 4 (Alert Burden) +
echo             5 (Feedback) + 6 (Drift) + 7 (Parity)
echo.

REM ----------------------------------------------------------
REM Phase 3 + 4: Supervised Baselines and Alert Burden
REM (Random Forest and Logistic Regression)
REM ----------------------------------------------------------
echo =========================================================
echo  Phase 3+4: Supervised Baselines (RF + LR) + Alert Burden
echo =========================================================

for %%S in (42 43 44 45 46) do (
    echo.
    echo ==== Random Forest seed %%S ====
    venv\Scripts\python.exe training\train_pipeline.py ^
        --model rf ^
        --data-dir data ^
        --output-dir models ^
        --seed %%S

    echo.
    echo ==== Logistic Regression seed %%S ====
    venv\Scripts\python.exe training\train_pipeline.py ^
        --model lr ^
        --data-dir data ^
        --output-dir models ^
        --seed %%S
)

echo.
echo =========================================================
echo  Phase 3+4: Unsupervised Baseline (Isolation Forest)
echo =========================================================

for %%S in (42 43 44 45 46) do (
    echo.
    echo ==== IsolationForest seed %%S ====
    venv\Scripts\python.exe training\isolation_forest.py ^
        --data-dir data ^
        --output-dir models ^
        --seed %%S
)

REM ----------------------------------------------------------
REM Aggregate Phase 3+4 metrics
REM ----------------------------------------------------------
echo.
echo =========================================================
echo  Aggregating Baseline Metrics
echo =========================================================
venv\Scripts\python.exe scripts\aggregate_metrics.py ^
    --models-dir models ^
    --output-dir docs

echo.
echo Baseline metrics written to:
echo   docs\summary_metrics.json
echo   docs\BASELINE_RESULTS.md

REM ----------------------------------------------------------
REM Phase 5: Simulated Analyst Feedback
REM ----------------------------------------------------------
echo.
echo =========================================================
echo  Phase 5: Time-Ordered Simulated Analyst Feedback
echo =========================================================
echo Budgets  : 50, 100, 250 labelled flows
echo Policies : none, random, top_alert, uncertainty
echo.
venv\Scripts\python.exe training\simulate_feedback.py ^
    --data-dir data ^
    --output-dir models

echo.
echo Feedback results written to:
echo   models\feedback_simulation_results.json

REM ----------------------------------------------------------
REM Phase 6: Drift Monitoring
REM ----------------------------------------------------------
echo.
echo =========================================================
echo  Phase 6: Unsupervised Drift Monitoring
echo =========================================================
venv\Scripts\python.exe training\drift_monitor.py ^
    --data-dir data ^
    --model-path models\pipeline_rf_day_based_seed42.pkl

echo.
echo Drift audit written to:
echo   docs\DRIFT_MONITORING.md

REM ----------------------------------------------------------
REM Phase 7: Feature Parity Audit
REM ----------------------------------------------------------
echo.
echo =========================================================
echo  Phase 7: Live Capture Feature Parity Audit
echo =========================================================
venv\Scripts\python.exe training\verify_feature_parity.py ^
    --model-path models\pipeline_rf_day_based_seed42.pkl ^
    --output-dir docs

echo.
echo Parity audit written to:
echo   docs\FEATURE_PARITY_LIVE_CAPTURE.md

REM ----------------------------------------------------------
REM Done
REM ----------------------------------------------------------
echo.
echo =========================================================
echo  All Experiment Phases Complete
echo =========================================================
echo.
echo Generated artifacts:
echo   models\pipeline_rf_*.pkl          (RF pipelines)
echo   models\pipeline_lr_*.pkl          (LR pipelines)
echo   models\pipeline_if_*.pkl          (IF pipelines)
echo   models\metrics_*.json             (per-seed metrics)
echo   models\feedback_simulation_results.json
echo   docs\summary_metrics.json
echo   docs\BASELINE_RESULTS.md
echo   docs\DRIFT_MONITORING.md
echo   docs\FEATURE_PARITY_LIVE_CAPTURE.md
echo   docs\RESEARCH_REPORT.md
echo.
echo To start the research workbench UI:
echo   venv\Scripts\python.exe app.py
echo.

