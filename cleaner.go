package verbose

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// KeyType holds the opening and closing boundary markers that delimit a class
// of sensitive content within a log string. Scrub replaces everything between
// (and including) Opening and Closing with the literal string "[CLEANED]".
//
// If Closing is empty, Scrub treats the next newline character as the closing
// boundary. This is useful for single-line token formats such as GitHub
// personal access tokens ("ghp_...").
//
// Gotcha: Opening must not be an empty string. AddKeyType silently ignores any
// KeyType whose Opening is empty because an empty opening string would cause
// Scrub's inner loop to match at index 0 on every iteration, potentially
// producing an infinite loop or corrupted output.
type KeyType struct {
	Opening string
	Closing string
}

// Regular expressions for cleaning yum output.
var (
	LastMetadataCheckRegex    = regexp.MustCompile(`(?m)^Last metadata expiration check:.*\n`)
	DependenciesResolvedRegex = regexp.MustCompile(`(?m)^Dependencies resolved\.\n=+\n.*\n=+\n`)
	TransactionSummaryRegex   = regexp.MustCompile(`(?m)^Transaction Summary\n=+\n.*\n\n`)
	RunningTransactionRegex   = regexp.MustCompile(`(?m)^Running transaction\n(?:.*\n)+^Complete!\n`)
	PackageDetailsRegex       = regexp.MustCompile(`(?m)^Installing:\n(?:.*\n)+^Complete!\n`)
	VerifyingRegex            = regexp.MustCompile(`(?m)^\s*Verifying\s*:.*\n(?:.*\n)*?`)
	TrimNewlinesRegex         = regexp.MustCompile(`\n+`)
	InstalledPackagesRegex    = regexp.MustCompile(`(?m)^Installed:\s*.*?\n`)
	UpdatedPackagesRegex      = regexp.MustCompile(`(?m)^Updated:\s*.*?\n`)
	DependencyUpdatedRegex    = regexp.MustCompile(`(?m)^Dependency Updated:\s*.*?\n`)
	CompleteMessageRegex      = regexp.MustCompile(`(?m)^Complete!\s*`)
	DownloadingPackagesRegex  = regexp.MustCompile(`(?m)^Downloading Packages:\n(?:.*\n)+^(\(\d+/\d+\): .*\n)+`)
	InstallingPackagesRegex   = regexp.MustCompile(`(?m)^(Installing|Upgrading|Removing|Erasing):.*\n(?:.*\n)*?^Complete!`)
)

// dockerRegexes lists regular expressions that match lines to keep in a Docker
// build output log.
var dockerRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^#\d+ building with ".+" instance using docker driver$`),
	regexp.MustCompile(`(?m)^(#\d+) \[internal\] .+$`),
	regexp.MustCompile(`(?m)^(#\d+) \[\d+/\d+\] (FROM|WORKDIR|COPY|RUN|CMD|ENTRYPOINT) .+$`),
	regexp.MustCompile(`(?m)^(#\d+) DONE \d+\.\ds$`),
	regexp.MustCompile(`(?m)^#\d+ exporting to image$`),
}

// yumRegexes gathers the yum-output patterns into a slice.
var yumRegexes = []*regexp.Regexp{
	DownloadingPackagesRegex,
	LastMetadataCheckRegex,
	InstallingPackagesRegex,
	PackageDetailsRegex,
	DependenciesResolvedRegex,
	RunningTransactionRegex,
	InstalledPackagesRegex,
	UpdatedPackagesRegex,
	DependencyUpdatedRegex,
	CompleteMessageRegex,
	TransactionSummaryRegex,
	VerifyingRegex,
}

// keyTypes defines the built-in set of opening/closing secret boundary pairs.
// All entries are protected by keyTypesMu.
var keyTypes = []KeyType{
	{"-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"},
	{"-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"},
	{"-----BEGIN DSA PRIVATE KEY-----", "-----END DSA PRIVATE KEY-----"},
	{"-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"},
	{"-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"},
	{"-----BEGIN EC PARAMETERS-----", "-----END EC PARAMETERS-----"},
	{`"ssh-`, `"`},
	{"SHA256:", "\n"},
	{"glpat-", "\n"}, // For GitLab personal access tokens
	{"ghp_", "\""},   // For GitHub personal access tokens
	{"DefaultEndpointsProtocol=https;AccountName=", "\""},       // For Azure DevOps
	{"\"type\": \"service_account\"", "}"},                      // For GCP DevOps
	{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ""},                // For JWT Tokens
	{"vault_approle_secret_id=", "\""},                          // For Vault AppRole IDs
	{"apiVersion: v1", "contexts:"},                             // For Kubernetes Configs
	{"sk_live_", "\""},                                          // For Stripe Keys
	{"aws_access_key_id=", "aws_secret_access_key="},            // For AWS DevOps
	{`{"auths":{"https://index.docker.io/v1/":{"auth":`, "}}}"}, // For Docker Configs
	{`"arn:aws:`, `",`},
	{"-----BEGIN PGP MESSAGE-----", "-----END PGP MESSAGE-----"},
	{"-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----END PGP PUBLIC KEY BLOCK-----"},
	{"-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----"},
	{"-----BEGIN PGP SIGNATURE-----", "-----END PGP SIGNATURE-----"},
	{"-----BEGIN PGP SIGNED MESSAGE-----", "-----END PGP SIGNED MESSAGE-----"},
	{"-----BEGIN ENCRYPTED MESSAGE-----", "-----END ENCRYPTED MESSAGE-----"},
	{"-----BEGIN SIGNATURE-----", "-----END SIGNATURE-----"},
}

// keyTypesMu protects keyTypes from concurrent reads and writes.
var keyTypesMu sync.RWMutex

// AddKeyType appends a custom KeyType to the list of patterns that Scrub will
// clean from log output. It is safe for concurrent use.
//
// AddKeyType enforces two invariants before appending:
//  1. kt.Opening must not be empty. An empty Opening would cause Scrub's inner
//     loop to match at byte offset 0 on every iteration, which can corrupt
//     output or loop indefinitely.
//  2. The (Opening, Closing) pair must not already be present. Duplicate
//     entries would cause Scrub to scan for and replace the same region twice,
//     wasting CPU and producing double-wrapped "[CLEANED][CLEANED]" output.
//
// Both violations are silently ignored (no error is returned) because
// AddKeyType is typically called at init time where error returns are
// inconvenient. Log a defensive check before calling if strict feedback is
// required.
//
// Performance: Scrub iterates over every registered KeyType for every log line.
// Each additional KeyType adds one full pass over the input string. Register
// only the patterns your application actually needs.
//
// Example:
//
//	verbose.AddKeyType(verbose.KeyType{
//	    Opening: "BEGIN_MY_SECRET",
//	    Closing: "END_MY_SECRET",
//	})
func AddKeyType(kt KeyType) {
	if kt.Opening == "" {
		return
	}
	keyTypesMu.Lock()
	defer keyTypesMu.Unlock()
	for _, existing := range keyTypes {
		if existing.Opening == kt.Opening && existing.Closing == kt.Closing {
			return
		}
	}
	keyTypes = append(keyTypes, kt)
}

// RemoveKeyType removes the first KeyType whose Opening matches kt.Opening
// from the list of patterns. It is safe for concurrent use.
//
// Example:
//
//	verbose.RemoveKeyType(verbose.KeyType{Opening: "BEGIN_MY_SECRET", Closing: "END_MY_SECRET"})
func RemoveKeyType(kt KeyType) {
	keyTypesMu.Lock()
	defer keyTypesMu.Unlock()
	for i, k := range keyTypes {
		if k.Opening == kt.Opening {
			keyTypes = append(keyTypes[:i], keyTypes[i+1:]...)
			return
		}
	}
}

// Scrub removes sensitive content from input by scanning for each registered
// KeyType boundary pair and replacing the matched region (including the
// boundaries) with the literal string "[CLEANED]". It then passes the result
// through Rinse to strip ANSI escape codes.
//
// Scrub is safe for concurrent use. It takes a read-lock on keyTypes,
// copies the slice, and releases the lock before performing any string
// operations.
//
// Patterns are applied sequentially in registration order. If multiple
// KeyTypes could match overlapping regions, the first registered pattern wins.
//
// Gotcha: Scrub operates on the raw string bytes. It does not parse structured
// formats (JSON, YAML, etc.). A JWT embedded inside a JSON value is cleaned
// correctly; a base64-encoded JWT is not recognised unless the base64 form
// happens to start with the configured Opening marker.
//
// Performance: O(k × n) where k is the number of registered KeyTypes and n is
// the length of input. Each KeyType requires at least one call to
// strings.Index. For most log lines this is fast, but callers should avoid
// passing multi-megabyte blobs through Scrub.
//
// Example:
//
//	cleaned := verbose.Scrub(rawLogLine)
func Scrub(input string) (output string) {
	input = Rinse(input)
	keyTypesMu.RLock()
	localKeyTypes := make([]KeyType, len(keyTypes))
	copy(localKeyTypes, keyTypes)
	keyTypesMu.RUnlock()
	for _, keyType := range localKeyTypes {
		for {
			start := strings.Index(input, keyType.Opening)
			if start == -1 {
				break
			}
			var end int
			if keyType.Closing == "" {
				end = strings.Index(input[start:], "\n")
				if end == -1 {
					end = len(input)
				} else {
					end += start
				}
			} else {
				end = strings.Index(input[start:], keyType.Closing)
				if end == -1 {
					break
				}
				end += start + len(keyType.Closing)
			}
			if end > start {
				input = input[:start] + "[CLEANED]" + input[end:]
			} else {
				break
			}
		}
	}
	output = strings.Clone(input)
	input = ""
	return
}

// Rinse strips ANSI escape codes from input and returns the cleaned string.
// It is called automatically by Scrub; callers that only need escape-code
// removal (without pattern-based secret cleaning) can call Rinse directly.
//
// Example:
//
//	plain := verbose.Rinse("\x1b[31mred text\x1b[0m")
//	// plain == "red text"
func Rinse(input string) (output string) {
	output = strings.Clone(input)
	output = RemoveAnsiEscapeCodes(output)
	return
}

// RegexRemoveAnsiEscapeCodes matches all ANSI CSI escape sequences of the form
// ESC [  m (SGR — Select Graphic Rendition).
var RegexRemoveAnsiEscapeCodes = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// RemoveAnsiEscapeCodes strips all ANSI SGR escape sequences from input and
// returns the resulting plain string.
//
// Example:
//
//	s := verbose.RemoveAnsiEscapeCodes("\x1b[1;32mOK\x1b[0m")
//	// s == "OK"
func RemoveAnsiEscapeCodes(input string) string {
	return RegexRemoveAnsiEscapeCodes.ReplaceAllString(input, "")
}

type secretPatternLength int
type secretPattern []string
type secretPatterns map[secretPatternLength]secretPattern

// Validate reports an error if sp is nil, empty, or contains any zero-length
// key or empty-value entry.
func (sp secretPatterns) Validate() error {
	if sp == nil || len(sp) == 0 {
		return fmt.Errorf("secretPatterns map is empty or nil")
	}
	for key, value := range sp {
		if key == 0 {
			return fmt.Errorf("invalid key: empty string")
		}
		if len(value) == 0 {
			return fmt.Errorf("invalid value for key %d: empty string", key)
		}
	}
	return nil
}

const (
	MaxSecretPatternLength int = 1024
	MinSecretPatternLength int = 3
	MinSecretLength        int = 3
	MaxSecretLength        int = 1024
)
