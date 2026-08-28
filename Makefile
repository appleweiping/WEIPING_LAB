# WEIPING_LAB

.PHONY: install test lint release-scan ui-lint ui-build ui-audit verify clean run-discover run-status

install:
	python -m pip install --upgrade "pip>=26.2.1" "setuptools>=84.0.0"
	python -m pip install -e ".[dev]"
	cp -n .env.example .env || true
	@echo ""
	@echo "  Add ANTHROPIC_API_KEY to .env"
	@echo "  Then: make run-status"

test:
	python -m pytest -q

lint:
	python scripts/run_ruff.py check lab/ cli/ api/ tests/ scripts/
	python scripts/run_ruff.py format --check lab/ cli/ api/ tests/ scripts/

release-scan:
	python scripts/release_scan.py

ui-lint:
	npm --prefix ui run lint

ui-build:
	npm --prefix ui run build

ui-audit:
	npm --prefix ui audit --audit-level=low --registry=https://registry.npmjs.org

verify: test lint release-scan ui-lint ui-build ui-audit
	python -m pip check
	python -m pip_audit

format:
	python scripts/run_ruff.py format lab/ cli/ api/ tests/ scripts/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .ruff_cache .mypy_cache

run-status:
	python -m cli.main status

run-discover:
	@read -p "Domain (e.g. LLM4Rec): " domain; \
	python -m cli.main discover "$$domain"

run-extend:
	@echo "Usage: python -m cli.main extend <domain> --method '...' --limits '...'"

help:
	@echo ""
	@echo "  make install      Install dependencies and copy .env.example"
	@echo "  make test         Run test suite"
	@echo "  make lint         Check code style"
	@echo "  make verify       Run tests, release scan, UI lint/build, and UI audit"
	@echo "  make format       Auto-format code"
	@echo "  make run-status   Check API key configuration"
	@echo "  make run-discover Start a discovery session"
	@echo ""
