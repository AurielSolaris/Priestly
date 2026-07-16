# Priestly -- WSS protocol build & test workflow.
# All Python runs through `uv run` so the project venv is always used.

PY := uv run
DIST := dist

.PHONY: help install cert test cov build build-server build-client run-server run-client run-ui clean

help:
	@echo "Targets:"
	@echo "  install       uv sync (deps + dev tools)"
	@echo "  cert          generate the self-signed dev certificate"
	@echo "  test          run the full test suite"
	@echo "  cov           run tests with coverage (term-missing report)"
	@echo "  build         compile both client and server binaries"
	@echo "  build-server  compile dist/priestly-server"
	@echo "  build-client  compile dist/priestly-client"
	@echo "  run-server    run the server from source"
	@echo "  run-client    run the client from source (TEXT=...)"
	@echo "  run-ui        run the client with the browser UI"
	@echo "  clean         remove build/test artifacts"

install:
	uv sync

cert:
	$(PY) python scripts/gen_dev_cert.py

test:
	$(PY) pytest

cov:
	$(PY) pytest --cov=transport --cov=protocol --cov=crypto --cov=cli --cov=config --cov-report=term-missing

build: build-server build-client

build-server:
	$(PY) pyinstaller --onefile --clean --noconfirm --name priestly-server --paths . cli/server.py

build-client:
	$(PY) pyinstaller --onefile --clean --noconfirm --name priestly-client --paths . cli/client.py

run-server:
	$(PY) python -m cli.server

TEXT ?= hello over WSS
run-client:
	$(PY) python -m cli.client "$(TEXT)"

run-ui:
	$(PY) python -m cli.client --ui

clean:
	rm -rf build $(DIST) *.spec .pytest_cache .coverage htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
