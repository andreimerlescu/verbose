# Verbose Package

A Go logging utility that automatically scrubs secrets from log output — passwords,
tokens, private keys, JWTs, and more — before they ever reach disk. Built for
production systems where a leaked credential in a log file is a breach.

## Why Verbose?

Most loggers will happily write your database password, API token, or private key
straight to disk. Verbose doesn't. Every string that passes through `Printf`,
`Println`, or any other log call is sanitized against a registry of secrets before
it is written. Secrets are stored only as SHA-512 hashes — the plaintext never
persists in memory longer than the call that registers it.

- **Automatic redaction** — register a secret once, it is scrubbed everywhere
- **Pattern-based cleaning** — PEM keys, JWTs, GitHub tokens, AWS credentials,
  Docker configs, Kubernetes configs, and more are cleaned automatically without
  registration
- **AES-GCM encryption** — `SecureBytes` provides authenticated encryption for
  sensitive values that need to travel through your application
- **Stack traces** — `Trace` and `TraceReturn` attach a full stack trace to any
  log line or returned error
- **Multi-logger support** — write sanitized output to any `*log.Logger` via `To`
- **Safe by default** — ANSI escape codes are stripped, overlapping secrets are
  merged correctly, concurrent registration and removal of secrets is race-free
- **Zero allocs on empty input** — the fast path costs 1.4 ns and touches no heap

## Installation

    go get -u github.com/andreimerlescu/verbose

## Quick Start

    package main

    import (
        "flag"
        "github.com/andreimerlescu/verbose"
    )

    func main() {
        err := verbose.NewLogger(verbose.Options{
            Truncate: true,
            Dir:      "/var/log/myapp",
            Name:     "myapp",
            FileMode: 0644,
            DirMode:  0755,
        })
        if err != nil {
            panic(err)
        }

        name   := flag.String("name",   "", "Name")
        secret := flag.String("secret", "", "Secret")
        flag.Parse()

        // register the secret — verbose will redact it everywhere from this point on
        if err := verbose.AddSecret(verbose.SecretBytes(*secret), "[REDACTED]"); err != nil {
            panic("failed to register secret: " + err.Error())
        }

        if len(*name) == 0 {
            panic(verbose.TracefReturn("invalid -name provided: %v", *name))
        }

        // bypass sanitization — prints the raw value to the verbose log
        verbose.Plain("The raw value is:", *secret)

        // this will redact the secret automatically
        verbose.Printf("Hello %s, your secret is safe: %s", *name, *secret)
    }

## Secret Registration

Secrets are hashed with SHA-512 on registration. The plaintext is never stored.

    // register with a custom replacement string
    verbose.AddSecret(verbose.SecretBytes("my-api-token"), "[API_TOKEN]")

    // remove when no longer needed
    verbose.RemoveSecret(verbose.SecretBytes("my-api-token"))

    // import pre-hashed secrets (e.g. loaded from a secrets manager)
    verbose.ImportSecrets(map[string]int{
        "abc123...sha512hex...": 32,
    })

## Pattern-Based Cleaning

The following are cleaned automatically from all log output without registration:

- PEM blocks (RSA, EC, DSA, OPENSSH, CERTIFICATE)
- PGP messages, signatures, and key blocks
- JWTs (`eyJhbGci...`)
- GitHub (`ghp_`), GitLab (`glpat-`), and Stripe (`sk_live_`) tokens
- AWS credentials, Docker auth configs, Kubernetes configs
- GCP service account JSON, Vault AppRole secrets, Azure connection strings

Custom patterns can be added at runtime:

    verbose.AddKeyType(verbose.KeyType{
        Opening: "BEGIN_MY_SECRET",
        Closing: "END_MY_SECRET",
    })

## Logging Functions

| Function | Sanitized | Description |
|----------|-----------|-------------|
| `Printf` / `Println` / `Print` | Yes | Standard log, secrets redacted |
| `Trace` / `Tracef` | Yes | Log with full stack trace |
| `Return` / `Returnf` | Yes | Log and return as `error` |
| `TraceReturn` / `TracefReturn` | Yes | Log with stack trace, return as `error` |
| `Plain` / `Raw` / `Expose` | No | Bypass sanitization entirely |
| `To` / `Tof` | Yes | Write sanitized output to any `*log.Logger` |

## Encryption

`SecureBytes` wraps a byte slice with AES-GCM encryption:

    data := verbose.SecureBytes("sensitive-value")

    encrypted, err := data.Encrypt()
    // data is now ciphertext in place

    plaintext, err := data.Decrypt()
    // data is restored

    // use a custom 16, 24, or 32 byte key
    verbose.SetKey("my-32-byte-key-goes-right-here!!")

## Performance

Measured on Apple M3 Ultra. All tests run with `-race`.

| Input size | Secrets registered | ns/op | B/op | allocs/op |
|------------|-------------------|-------|------|-----------|
| 0 bytes | any | 1.4 | 0 | 0 |
| 10 bytes | any | 11,394 | 19,608 | 12 |
| 80 bytes | any | 72,649 | 99,112 | 689 |
| 640 bytes | any | 1,580,327 | 2,219,627 | 16,382 |
| 2560 bytes | any | 9,131,123 | 13,063,797 | 85,502 |

The algorithm is O(n²) in input length — intentionally, because every substring
must be checked against the secret registry. For typical log lines under 200 bytes
the overhead is imperceptible. `AddSecret` costs 315 ns. `RemoveSecret` costs 247 ns.

Run the benchmarks yourself:

    git clone git@github.com:andreimerlescu/verbose.git
    cd verbose
    make bench

## Contributing

Bug reports, test cases, and new `KeyType` patterns for common credential formats
are very welcome. Open an issue or a pull request.

## License

Apache 2.0
