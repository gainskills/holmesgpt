.PHONY: docs

check:
	poetry run pre-commit run -a


test-llm-ask-holmes:
	poetry run pytest tests/llm/test_ask_holmes.py -n 6 -vv

test-without-llm:
	poetry run pytest tests -m "not llm"

docs:
	poetry run mkdocs serve --dev-addr=127.0.0.1:7000

docs-build:
	poetry run mkdocs build

docs-strict:
	poetry run mkdocs serve --dev-addr=127.0.0.1:7000 --strict

dev-build:
	docker build -t robustadev/holmes:dev .
	docker build -f Dockerfile.operator -t robustadev/holmes-operator:dev .

dev-reload:
	./scripts/dev-reload.sh
