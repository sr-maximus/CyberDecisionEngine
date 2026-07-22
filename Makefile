.PHONY: install test demo health web-up web-down web-logs web-local web-local-stop clean

install:
	python3.13 -m venv .venv
	. .venv/bin/activate && python -m pip install --upgrade pip
	. .venv/bin/activate && python -m pip install -e ".[dev]"

test:
	python -m pytest -q

demo:
	scripts/run_demo.sh

health:
	scripts/healthcheck.sh

web-up:
	-scripts/stop_local_web.sh
	docker compose up --build -d

web-down:
	docker compose down

web-logs:
	docker compose logs -f

web-local:
	scripts/start_local_web.sh

web-local-stop:
	scripts/stop_local_web.sh

clean:
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
