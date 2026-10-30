.PHONY: install run test lint docker-up docker-down analyze-sample

install:
	pip install -e ".[dev]"

run:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest -v

lint:
	ruff check app tests
	mypy app

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

analyze-sample:
	curl -s -X POST http://localhost:8001/api/v1/analysis \
		-H "Content-Type: application/json" \
		-d '{"local_path": "tests/fixtures/sample_vulnerable_repo", "analysis_profile": "mvp-default", "model_profile": "default", "enable_remediation": true}' | tee /tmp/analyze-sample-response.json
