# MEME protocol. See AGENTS.md for how to work in this repository.
SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help install lint types unit conformance vectors check

help: ## List targets
	@grep -hE '^[a-z0-9-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "} {printf "  %-12s %s\n", $$1, $$2}'

install: ## Install dependencies from the lockfile
	pnpm install --frozen-lockfile

lint: ## ESLint and Prettier
	pnpm -s lint

types: ## TypeScript
	pnpm -s typecheck

unit: ## Unit tests, including every vector and a check that vectors/ is up to date
	pnpm -s test

conformance: ## Run every vector through the reference library and print the results
	pnpm -s conformance

vectors: ## Regenerate vectors/ after changing conformance/build-vectors.ts
	pnpm -s vectors

check: lint types unit conformance ## Everything CI runs
