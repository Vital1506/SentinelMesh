PYTHON ?= python
COMPOSE ?= docker compose

.PHONY: install run test docker lint

install:
	$(PYTHON) -m pip install -e .[dev,intel,analytics,ssh]

run:
	$(PYTHON) -m sentinelmesh serve

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy sentinelmesh

docker:
	$(COMPOSE) -f deploy/docker-compose.yml up --build
