.PHONY: all test test-verbose serve mcp clean install build lint help

PYTHON ?= python3
PYTEST ?= pytest

all: test

help:
	@echo "SubSweep Lead Scanner - Make Commands"
	@echo "====================================="
	@echo "make test          - Run full pytest test suite"
	@echo "make test-verbose  - Run test suite with verbose output"
	@echo "make serve         - Start Material 3 Recon Studio Web UI on port 8090"
	@echo "make mcp           - Launch Model Context Protocol stdio server"
	@echo "make scan DOMAIN=x - Run full audit on a domain"
	@echo "make install       - Install package locally in editable mode"
	@echo "make build         - Build sdist and wheel artifacts"
	@echo "make clean         - Clean bytecode, caches and build artifacts"

test:
	PYTHONPATH=src $(PYTEST) tests/

test-verbose:
	PYTHONPATH=src $(PYTEST) tests/ -v -s

serve:
	PYTHONPATH=src $(PYTHON) -m subsweep_lead_scanner serve --port 8090

mcp:
	PYTHONPATH=src $(PYTHON) -m subsweep_lead_scanner mcp

scan:
	@if [ -z "$(DOMAIN)" ]; then echo "Usage: make scan DOMAIN=example.com"; exit 1; fi
	PYTHONPATH=src $(PYTHON) -m subsweep_lead_scanner scan $(DOMAIN)

install:
	$(PYTHON) -m pip install -e .

build:
	$(PYTHON) -m build

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	rm -rf .pytest_cache/ build/ dist/ *.egg-info/ .coverage
