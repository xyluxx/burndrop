# burndrop build and check targets. GNU make; on Windows use Git Bash.
# `make help` lists everything.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

VERSION ?= dev
GO_PKGS := $(shell go list ./... 2>/dev/null | grep -v /node_modules/)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: help build web e2e screenshots test race lint typecheck hygiene instructions coverage docker sdk-python sdk-typescript extension interop clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

build: ## Build both binaries into bin/ (run `make web` first to embed the page)
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ ./cmd/burndrop ./cmd/burndrop-relay

web: ## Build the drop page (web/dist) and run its unit tests
	cd web && npm ci --no-audit --no-fund && npm run typecheck && node build.mjs --version "$(VERSION)" && npx vitest run --coverage

e2e: ## Playwright suite against a real relay (needs: cd web && npx playwright install chromium)
	cd web && node e2e/build-relay.mjs && npx playwright test

screenshots: ## Regenerate docs/screenshots from the real page (needs ffmpeg and the Playwright browser)
	cd web && node e2e/build-relay.mjs && BURNDROP_SCREENSHOTS=1 npx playwright test --project=screenshots
	ffmpeg -y -loglevel error -i docs/screenshots/demo.webm -vf "fps=12,scale=600:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=128[p];[s1][p]paletteuse=dither=bayer:bayer_scale=5" -loop 0 docs/screenshots/demo.gif
	rm -f docs/screenshots/demo.webm

test: ## Go unit tests
	go test -count=1 $(GO_PKGS)

race: ## Go unit tests with the race detector and coverage
	go test -race -count=1 -coverprofile=coverage.out $(GO_PKGS)
	go tool cover -func=coverage.out | tail -1

lint: ## gofmt, go vet, and the TypeScript type check
	@test -z "$$(gofmt -l cmd internal web)" || (gofmt -l cmd internal web && echo "gofmt: files need formatting" && exit 1)
	go vet $(GO_PKGS)
	cd web && npm run typecheck

typecheck: lint ## Alias for lint

hygiene: ## Em dash, attribution, pinned actions, and generated file checks
	@if git grep -I -l -P '\x{2014}' -- ':!*.woff2' ':!*.png' 2>/dev/null; then echo "em dash character found"; exit 1; fi
	@if git grep -I -n -i -E 'Co-Authored-By:.*(Claude|GPT|Copilot|Gemini|Anthropic|OpenAI)|Generated (with|by) (Claude|GPT|Copilot|Gemini|AI)' -- ':!.github/workflows/hygiene.yml' ':!Makefile' 2>/dev/null; then echo "attribution text found"; exit 1; fi
	@bad=0; for u in $$(grep -rhoE 'uses:\s*[^ ]+@[^ ]+' .github/workflows | sed -E 's/uses:\s*//'); do ref="$${u##*@}"; [[ "$$ref" =~ ^[0-9a-f]{40}$$ ]] || { echo "unpinned action: $$u"; bad=1; }; done; exit $$bad
	@go build -o "$${TMPDIR:-/tmp}/burndrop-hygiene" ./cmd/burndrop
	@for f in agents:AGENTS.md claude:CLAUDE.md cursor:cursor-rules/burndrop.mdc mcp-json:mcp/mcp.json vscode-mcp-json:mcp/vscode-mcp.json text:system-prompt.txt; do "$${TMPDIR:-/tmp}/burndrop-hygiene" instructions -format "$${f%%:*}" | diff - "agent-instructions/$${f#*:}"; done
	@echo "hygiene ok"

instructions: ## Regenerate agent-instructions/ from the binary
	go run ./cmd/burndrop instructions -format agents > agent-instructions/AGENTS.md
	go run ./cmd/burndrop instructions -format claude > agent-instructions/CLAUDE.md
	go run ./cmd/burndrop instructions -format cursor > agent-instructions/cursor-rules/burndrop.mdc
	go run ./cmd/burndrop instructions -format mcp-json > agent-instructions/mcp/mcp.json
	go run ./cmd/burndrop instructions -format vscode-mcp-json > agent-instructions/mcp/vscode-mcp.json
	go run ./cmd/burndrop instructions -format text > agent-instructions/system-prompt.txt

coverage: race ## HTML coverage report at coverage.html
	go tool cover -html=coverage.out -o coverage.html

docker: ## Build the relay container image
	docker build --build-arg VERSION="$(VERSION)" -t burndrop-relay:$(VERSION) .

sdk-python: ## Python SDK tests
	cd sdk/python && uv sync --frozen && uv run pytest

sdk-typescript: ## TypeScript SDK tests
	cd sdk/typescript && npm ci --no-audit --no-fund && npm test

extension: ## Build and test the browser extension
	cd extension && npm ci --no-audit --no-fund && npm run e2e:build-relay && npm run build && npm test

interop: ## Cross-language interop: each language generates, every language checks
	cd sdk/python && uv run python ../../spec/interop/python_gen.py
	cd sdk/typescript && npm run interop:gen
	go run ./spec/interop/go gen
	go run ./spec/interop/go check
	cd sdk/python && uv run python ../../spec/interop/python_check.py
	cd sdk/typescript && npm run interop:check

clean: ## Remove build output
	rm -rf bin coverage.out coverage.html web/dist/page.html web/dist/page.meta.json web/dist/page.sha256 web/build extension/dist
