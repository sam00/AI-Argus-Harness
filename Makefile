# AI-Argus-Harness — common tasks. Run `make help` for the list.
PY ?= python3

.DEFAULT_GOAL := help
.PHONY: help install install-dev install-pipx test smoke scan-demo init-config docker-build docker-scan clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## Install the harness (core, zero hard deps)
	$(PY) -m pip install -e .

install-dev: ## Install with YAML + dev/test extras
	$(PY) -m pip install -e ".[yaml,dev]"

install-pipx: ## Isolated install via pipx (recommended for operators)
	pipx install .

test: ## Run the unit + regression suite
	$(PY) -m pytest -q

smoke: ## Quick CLI smoke check (offline)
	$(PY) -m ai_argus version && $(PY) -m ai_argus doctor && $(PY) -m ai_argus stages

scan-demo: ## Run the bundled offline demo scan
	$(PY) -m ai_argus scan ./examples/demo-target --offline --no-auth-scan \
		--path ./examples/demo-target --inventory examples/inventory.json

init-config: ## Seed a global config from the example template
	mkdir -p $${AI_ARGUS_HOME:-$$HOME/.config/ai-argus}
	cp -n examples/config.example.json $${AI_ARGUS_HOME:-$$HOME/.config/ai-argus}/config.json
	@echo "Wrote $${AI_ARGUS_HOME:-$$HOME/.config/ai-argus}/config.json (edit provider/budget as needed)"

docker-build: ## Build the container image
	docker build -t ai-argus-harness .

docker-scan: ## Run the demo scan inside the container
	docker run --rm -v "$$PWD":/work ai-argus-harness \
		scan /work/examples/demo-target --offline --no-auth-scan \
		--path /work/examples/demo-target --inventory /work/examples/inventory.json

clean: ## Remove caches and local run artifacts
	rm -rf argus-runs .pytest_cache **/__pycache__ *.egg-info build dist
