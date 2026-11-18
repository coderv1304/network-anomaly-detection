@echo off
rem Run from the repository root so relative data/model paths resolve.
cd /d "%~dp0..\.."
docker build -t nd_capture:latest -f Dockerfile.capture .
