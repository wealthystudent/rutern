.PHONY: check test lint typecheck live fixtures

check: lint typecheck test

test:
	uv run pytest -q

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run mypy

live:
	uv run pytest -q -m live

fixtures:
	uv run python scripts/record_fixtures.py local cloud
