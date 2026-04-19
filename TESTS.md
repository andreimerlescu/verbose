# Testing Guide

This document covers the testing strategy, how to run the test suite, what each
category of test covers, and how the GitHub Actions CI pipeline is structured.

---

## Running the Tests

### Full CI pipeline (recommended)

    make ci

Runs `go mod tidy`, `go mod verify`, `go vet`, the full race-detected test suite,
and all benchmarks in sequence. This is what the GitHub Actions workflow runs on
every push and pull request.

### Tests only

    make test

Runs all tests with verbose output and `-count=1` to prevent result caching.

### Tests with race detector

    make test-race

Runs all tests under the Go race detector. This package uses multiple `sync.RWMutex`
instances across concurrent map operations and this flag is mandatory before any
merge. A test that passes without `-race` but fails with it is a real bug.

### Repeat runs (intermittent failure detection)

    make test-repeat

Runs the full suite 10 times in a single invocation. Use `COUNT=n` to override:

    make test-repeat COUNT=50

Useful for catching timing-sensitive failures in the concurrent tests such as
`TestCommitHashConcurrent` and `Test_SetKeyConcurrent`.

### Short mode

    make test-short

Skips any test that calls `t.Skip` under `testing.Short()`. Currently all tests
run in short mode but this flag is wired up for future use.

---

## Fuzz Testing

Each fuzz target can be run individually for a configurable duration. The default
is 30 seconds. Override with `FUZZ_TIME`:

    make fuzz-scrub       FUZZ_TIME=5m
    make fuzz-sanitize    FUZZ_TIME=5m
    make fuzz-sha512      FUZZ_TIME=5m
    make fuzz-encrypt     FUZZ_TIME=5m

Run all fuzz targets back to back:

    make fuzz FUZZ_TIME=2m

Fuzz targets run their seeded corpus under plain `go test` — you will see them
appear in normal test output as `FuzzX/seed#N` cases and they count toward the
pass/fail result without adding unbounded runtime to CI. To run the fuzzer in
generative mode (actually mutating inputs to find new failures), use the
`make fuzz-*` targets directly outside of CI.

If the fuzzer finds a failing input it writes it to `testdata/fuzz/<FuzzTarget>/`
as a corpus file. That file is then replayed on every subsequent run of that fuzz
target. Commit these files to the repository so the edge case is covered
permanently.

---

## Coverage

    make cover

Runs the full test suite with coverage instrumentation and prints a per-function
summary to stdout.

    make cover-html

Same as above but opens an interactive HTML report in your browser showing
covered and uncovered lines side by side.

---

## Test Structure

### `cleaner_test.go`

Tests for the `Scrub`, `Rinse`, `AddKeyType`, `RemoveKeyType`, `AddSecretEnv`,
`RemoveSecretEnv`, and `IsSecretEnv` functions.

| Test | What it covers |
|------|----------------|
| `TestCleaner` | Table-driven: verifies PEM blocks, JWTs, Docker auth configs, and plain text are handled correctly by `Scrub` |
| `TestAddKeyType` | Custom `KeyType` registered at runtime is cleaned from output |
| `TestRemoveSecretEnv` | Env substring removed via `RemoveSecretEnv` no longer matches `IsSecretEnv` |
| `TestAddSecretEnvNoDuplicates` | `AddSecretEnv` is idempotent — duplicate entries are not added |
| `TestSecretEnvsConcurrent` | 100 concurrent goroutines calling `AddSecretEnv`, `RemoveSecretEnv`, and `IsSecretEnv` simultaneously — race detector must pass |
| `TestKeyTypesConcurrent` | 100 concurrent goroutines calling `AddKeyType`, `RemoveKeyType`, and `Scrub` simultaneously — race detector must pass |

### `sanitize_test.go`

Tests for `sanitizeInput` and its overlap-merging behaviour.

| Test | What it covers |
|------|----------------|
| `TestSanitizeOverlappingSecrets` | `"supersecret"` and `"secret"` are both registered; input containing `"supersecret"` must not produce corrupt output like `"super[INNER]"` |
| `BenchmarkSanitize` | Cross-product of 10 input lengths × 7 secret sizes — measures throughput and allocations of the full sanitization path |
| `BenchmarkSanitizeNoSecrets` | Same input lengths with no secrets registered — measures the cost of the early-exit fast path |

### `secrets_test.go`

Tests for `AddSecret`, `RemoveSecret`, `ImportSecrets`, `commitHash`, and `IsSecret`.

| Test | What it covers |
|------|----------------|
| `TestAddSecret` | Table-driven: rejects secrets below `SecretMinLength`, accepts valid secrets |
| `TestRemoveSecret` | Five secrets added then removed in reverse order — all succeed |
| `TestImportSecretsCount` | Table-driven: all-valid, all-invalid, and mixed maps — verifies the returned count matches only successful imports |
| `TestImportSecretsPartialImport` | A valid hash survives a partial import that also contains an invalid hash |
| `TestCommitHashConcurrent` | 20 goroutines each calling `commitHash` simultaneously — verifies all hashes are present and correct after `WaitGroup` completes, and that `min`/`max` are consistent |
| `TestCommitHashInvalidInputs` | Table-driven: wrong hash length, zero length, empty `replaceWith`, valid inputs |
| `TestIsSecretEnv` | Placeholder — to be expanded |
| `BenchmarkAddSecret` | Per-operation cost of `AddSecret` including SHA-512 and map write |
| `BenchmarkRemoveSecret` | Per-operation cost of `RemoveSecret` including SHA-512 and map delete |

### `secret_bytes_test.go`

Tests for `SecretBytes.Sha512` and the `ImportSecrets` boundary.

| Test | What it covers |
|------|----------------|
| `TestSecretBytes_Sha512` | Table-driven: valid input produces a 128-character hex string; input below `SecretMinLength` returns an error |
| `TestImportSecrets` | Two known hashes imported, verified present via `IsSecret`, then removed via `RemoveSecret` |

### `secure_bytes_test.go`

Tests for `SecureBytes` encryption, decryption, and key management.

| Test | What it covers |
|------|----------------|
| `TestGenerateEncryptionKey` | Generated key is non-empty and exactly `keyLength` bytes |
| `TestEncrypt` | Encrypted output differs from input and `IsEncrypted` returns true |
| `TestDecrypt` | Round-trip encrypt then decrypt recovers the original plaintext |
| `TestIsEncrypted` | `IsEncrypted` returns false before encryption and true after |
| `TestEncryptAlreadyEncrypted` | Calling `Encrypt` on already-encrypted data returns an error |
| `TestDecryptNotEncrypted` | Calling `Decrypt` on plaintext returns the original string without error |
| `TestSetKeyInvalidLength` | Table-driven: 15, 16, 24, 32, 33, and empty key lengths — only 16, 24, and 32 are accepted |
| `Test_SetKeyConcurrent` | 100 goroutines calling `SetKey` while 100 more goroutines call `EncryptUsingKey`/`DecryptUsingKey` with a fixed local key — race detector must pass |

### `verbose_test.go`

Integration tests for the top-level package API.

| Test | What it covers |
|------|----------------|
| `TestGuard` | With `vLogr` set to nil: `TraceReturn` and `Return` return non-nil errors; `SetLogger(nil)` returns an error and does not modify `vLogr` |
| `TestVerboseLogging` | Full end-to-end: initialises a logger to a temp directory, registers a secret, logs a line containing the secret, reads the log file and verifies the secret is redacted, removes the secret, logs again and verifies the plaintext now appears |

### `fuzz_test.go`

Property-based fuzz targets. Run as seed-corpus tests in CI and as generative
fuzzers when invoked directly.

| Target | What it covers |
|--------|----------------|
| `FuzzScrub` | `Scrub` never panics on arbitrary input; valid UTF-8 input always produces valid UTF-8 output; output never grows unboundedly |
| `FuzzSanitizeInput` | `sanitizeInput` never panics; a registered secret (`"fuzzSecret99"`) never appears in output for any input |
| `FuzzSecretBytesSha512` | `Sha512` never returns both a hash and an error simultaneously; valid-length input always produces a 128-character hex string |
| `FuzzEncryptDecrypt` | Encrypting then decrypting any input always recovers the original plaintext |

---

## GitHub Actions Workflow

The workflow lives at `.github/workflows/go.yml` and triggers on every push and
pull request to `master`.

### Matrix

    go-version: ["1.23.4"]

A single Go version is pinned to match `go.mod`. Add versions to the matrix to
test forward compatibility when upgrading.

### Steps

| Step | Command | Purpose |
|------|---------|---------|
| Checkout | `actions/checkout@v4` | Fetch the repository |
| Set up Go | `actions/setup-go@v5` | Install the pinned Go version with module cache enabled |
| Verify dependencies | `go mod verify` | Confirm no dependency has been tampered with since `go.sum` was written |
| Vet | `go vet ./...` | Static analysis — catches common correctness issues before tests run |
| Test | `go test -v -race -count=1 ./...` | Full test suite with race detector, caching disabled |
| Benchmark | `go test -v -run='^$' -bench=. -benchmem ./...` | All benchmarks with memory profiling — output is visible in the Actions log for manual comparison across runs |

### Notes

Benchmarks run in CI but do not gate the build. Their output is preserved in the
Actions log so regressions can be spotted by comparing runs. If you want to
enforce a performance budget, add a step that pipes benchmark output through
`benchstat` and fails on a statistically significant regression.

The race detector is non-negotiable in CI for this package. The secret registry,
the key type list, the encryption key, and the secret env list are all shared
mutable state protected by `sync.RWMutex`. A missed lock acquisition will not
reliably manifest as a test failure without `-race`.

---

## Adding a New Test

1. Write the test in the appropriate `_test.go` file for the file under test.
2. If the test exercises concurrent behaviour, verify it passes under
   `make test-race` before opening a pull request.
3. If the test covers a new input shape for `Scrub` or `sanitizeInput`, consider
   adding it as a seed to the corresponding fuzz target in `fuzz_test.go` so the
   fuzzer explores mutations from that shape automatically.
4. Run `make ci` locally before pushing. The GitHub Actions workflow runs the
   same commands and a local failure is faster to debug than a CI failure.​​​​​​​​​​​​​​​​
