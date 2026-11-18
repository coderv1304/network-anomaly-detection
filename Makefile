# Single-word entry points for Linux, macOS, and WSL developers.
# Windows users have the same steps in scripts/windows/*.bat.

SHELL := /bin/bash

# Prefer .venv (created by `make setup`); fall back to an existing venv/.
VENV ?= $(if $(wildcard .venv),.venv,$(if $(wildcard venv),venv,.venv))

ifeq ($(OS),Windows_NT)
VENV_PY := $(VENV)/Scripts/python.exe
else
VENV_PY := $(VENV)/bin/python
endif

PYTHON ?= python3
# Fixed default so a stray PORT in the shell cannot move the demo off :5000.
# Override per invocation with `make run PORT=8080`.
PORT = 5000

.PHONY: help setup venv run test lint docker clean

help:
	@echo "make setup   create $(VENV) and install requirements.txt"
	@echo "make run     serve the operator console on http://localhost:$(PORT)"
	@echo "make test    run the pytest suite"
	@echo "make lint    ruff plus JavaScript syntax checks"
	@echo "make docker  build and start the local compose stack"

setup: venv
	$(VENV_PY) -m pip install --upgrade pip
	$(VENV_PY) -m pip install -r requirements.txt

venv:
	@test -d $(VENV) || $(PYTHON) -m venv $(VENV)

run:
	PORT=$(PORT) $(VENV_PY) app.py

test:
	$(VENV_PY) -m pytest tests -q

lint:
	$(VENV_PY) -m ruff check .
	node --check static/js/console.js
	node --check static/js/workbench.js

docker:
	docker compose up --build

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache
