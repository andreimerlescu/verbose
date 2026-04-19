# Makefile for github.com/andreimerlescu/verbose

SHELL        := /bin/bash
MODULE       := github.com/andreimerlescu/verbose
BINARY_DIR   := bin
FUZZ_TIME    ?= 30s
FUZZ_CORPUS  := testdata/fuzz
GO           := go
GOFLAGS      ?=

.DEFAULT_GOAL := help

# ─── Help ────────────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' \
		| sort

# ─── Dependencies ────────────────────────────────────────────────────────────

.PHONY: tidy
tidy: ## Tidy and verify go.mod / go.sum
	$(GO) mod tidy
	$(GO) mod verify

# ─── Build ───────────────────────────────────────────────────────────────────

.PHONY: build
build: ## Build the package (compile check only, no binary output)
	$(GO) build $(GOFLAGS) ./...

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

# ─── Test ────────────────────────────────────────────────────────────────────

.PHONY: test
test: ## Run all tests
	$(GO) test -v -count=1 ./...

.PHONY: test-race
test-race: ## Run all tests with the race detector
	$(GO) test -v -race -count=1 ./...

.PHONY: test-short
test-short: ## Run tests in short mode (skips slow tests)
	$(GO) test -v -short -count=1 ./...

.PHONY: test-repeat
test-repeat: ## Run tests 10 times to catch intermittent failures (use COUNT=n to override)
	$(GO) test -v -race -count=$(or $(COUNT),10) ./...

# ─── Benchmarks ──────────────────────────────────────────────────────────────

.PHONY: bench
bench: ## Run all benchmarks
	$(GO) test -v -run='^$$' -bench=. -benchmem ./...

.PHONY: bench-sanitize
bench-sanitize: ## Run only sanitize benchmarks
	$(GO) test -v -run='^$$' -bench=BenchmarkSanitize -benchmem ./...

.PHONY: bench-secrets
bench-secrets: ## Run only secret benchmarks
	$(GO) test -v -run='^$$' -bench=BenchmarkAdd -benchmem ./...
	$(GO) test -v -run='^$$' -bench=BenchmarkRemove -benchmem ./...

# ─── Fuzz ────────────────────────────────────────────────────────────────────

.PHONY: fuzz
fuzz: fuzz-scrub fuzz-sanitize fuzz-sha512 fuzz-encrypt ## Run all fuzz targets (FUZZ_TIME=30s)

.PHONY: fuzz-scrub
fuzz-scrub: ## Fuzz the Scrub function (FUZZ_TIME=30s)
	$(GO) test -fuzz=FuzzScrub -fuzztime=$(FUZZ_TIME) ./...

.PHONY: fuzz-sanitize
fuzz-sanitize: ## Fuzz sanitizeInput (FUZZ_TIME=30s)
	$(GO) test -fuzz=FuzzSanitizeInput -fuzztime=$(FUZZ_TIME) ./...

.PHONY: fuzz-sha512
fuzz-sha512: ## Fuzz SecretBytes.Sha512 (FUZZ_TIME=30s)
	$(GO) test -fuzz=FuzzSecretBytesSha512 -fuzztime=$(FUZZ_TIME) ./...

.PHONY: fuzz-encrypt
fuzz-encrypt: ## Fuzz the Encrypt/Decrypt round-trip (FUZZ_TIME=30s)
	$(GO) test -fuzz=FuzzEncryptDecrypt -fuzztime=$(FUZZ_TIME) ./...

# ─── Coverage ────────────────────────────────────────────────────────────────

.PHONY: cover
cover: ## Run tests and display coverage summary
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -func=coverage.out

.PHONY: cover-html
cover-html: cover ## Open coverage report in browser
	$(GO) tool cover -html=coverage.out

# ─── CI ──────────────────────────────────────────────────────────────────────

.PHONY: ci
ci: tidy vet test-race bench ## Full CI pipeline (tidy, vet, race tests, benchmarks)

# ─── Clean ───────────────────────────────────────────────────────────────────

.PHONY: clean
clean: ## Remove generated files and fuzz corpus artifacts
	rm -f coverage.out
	rm -rf $(FUZZ_CORPUS)
	@$(GO) clean ./...

# ─── Utilities ───────────────────────────────────────────────────────────────

.PHONY: version
version: ## Print the module version from verbose.go
	@grep -E '^const VERSION' verbose.go | awk '{print $$4}' | tr -d '"'