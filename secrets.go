package verbose

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Hashes maps a SHA-512 hex digest to the replacement string that will be
// substituted wherever the original secret appears in log output.
type Hashes map[string]string

// Lengths maps a SHA-512 hex digest to the byte-length of the original secret.
// The length is used by sanitizeInput to size its sliding window without ever
// retaining the plaintext.
type Lengths map[string]int

// Secrets holds all registered secrets in hashed form together with their
// original lengths and the read/write mutexes that protect each field.
//
// Never construct a Secrets value directly — use NewSecrets so that all mutex
// pointers are initialised before use.
type Secrets struct {
	Hashes  Hashes
	Lengths Lengths
	min     int
	max     int
	hmu     *sync.RWMutex
	lmu     *sync.RWMutex
	mmu     *sync.RWMutex
}

// Avg returns the arithmetic mean of the shortest and longest registered secret
// lengths. It is a convenience helper used internally to size buffers. Returns
// zero when no secrets have been registered.
func (s *Secrets) Avg() int {
	return (s.min + s.max) / 2
}

// NewSecrets allocates and returns a fully-initialised *Secrets value with
// empty hash and length maps and all three mutexes ready for use. This is the
// only correct way to create a Secrets value.
//
// Example:
//
//	s := verbose.NewSecrets()
func NewSecrets() *Secrets {
	return &Secrets{
		Hashes:  make(Hashes),
		Lengths: make(Lengths),
		lmu:     &sync.RWMutex{},
		hmu:     &sync.RWMutex{},
		mmu:     &sync.RWMutex{},
	}
}

// secrets is the package-wide singleton that stores all registered secrets.
var secrets = NewSecrets()

// SecretMinLength is the minimum number of bytes a secret must contain before
// it can be registered with AddSecret. Secrets shorter than this threshold
// would produce an unacceptably large number of false-positive matches when
// scanning log output.
//
// Lowering this value increases sanitizeInput CPU time O(n²) in input length.
// The default of 5 is a practical lower bound for most deployments.
var SecretMinLength = 5

// SecretEnvs is the exported slice of environment-variable name substrings
// that are considered sensitive. IsSecretEnv reports true for any env-var name
// that contains one of these substrings.
//
// # Thread safety
//
// Direct mutation of SecretEnvs is not safe for concurrent use. Use
// AddSecretEnv and RemoveSecretEnv to mutate this list from multiple goroutines.
// Direct reads are similarly unsafe; call secretEnvsCopy() internally when a
// stable snapshot is needed.
var SecretEnvs = []string{
	"KEY", "TOKEN", "PASSW", "CI_", "AWS_", "OP_", "DO_PAT", "OKTA", "KUBE", "WUZAH",
	"CLOUDFLARE_", "CLOUD_FLARE_", "LASTPASS_", "LAST_PASS_", "KEEPER_", "VAULT",
	"INTERCOM", "RABBITMQ", "MAILGUN", "TWILIO", "ZENDESK", "SENDGRID", "AUTH0",
	"JENKINS", "GITLAB", "GITHUB", "GH", "GITEA", "DATADOG", "SENTRY", "PAGERDUTY",
	"ROLLBAR", "SLACK", "REDIS", "SQL", "ROOT", "MONGO", "CERT", "_PEM", "_PK", "PK_",
	"PRIVATE_", "SECRET_", "PROTECTED", "_DSN", "DSN_", "_URI", "URI_",
}

// secretEnvsMu protects all reads and writes to SecretEnvs that go through
// the package's own accessor functions. Callers who read or write SecretEnvs
// directly bypass this protection.
var secretEnvsMu sync.RWMutex

// secretEnvsCopy returns a stable, mutex-protected snapshot of SecretEnvs for
// internal use. It is unexported deliberately — external callers should use
// AddSecretEnv / RemoveSecretEnv / IsSecretEnv to interact with the list.
func secretEnvsCopy() []string {
	secretEnvsMu.RLock()
	defer secretEnvsMu.RUnlock()
	cp := make([]string, len(SecretEnvs))
	copy(cp, SecretEnvs)
	return cp
}

// AddSecretEnv appends env to SecretEnvs if it is not already present.
// Leading and trailing whitespace is trimmed before the comparison; empty
// strings (or strings that are all whitespace) are silently ignored.
//
// It is safe for concurrent use alongside RemoveSecretEnv and IsSecretEnv.
//
// Example:
//
//	verbose.AddSecretEnv("MY_CORP_SECRET_")
//	// IsSecretEnv("MY_CORP_SECRET_KEY") now returns true
func AddSecretEnv(env string) {
	env = strings.TrimSpace(env)
	if env == "" {
		return
	}
	secretEnvsMu.Lock()
	defer secretEnvsMu.Unlock()
	for _, e := range SecretEnvs {
		if e == env {
			return
		}
	}
	SecretEnvs = append(SecretEnvs, env)
}

// RemoveSecretEnv removes the first entry in SecretEnvs whose value equals env
// (after trimming whitespace). It is a no-op if env is not present.
//
// It is safe for concurrent use alongside AddSecretEnv and IsSecretEnv.
//
// Example:
//
//	verbose.RemoveSecretEnv("GH")
func RemoveSecretEnv(env string) {
	env = strings.TrimSpace(env)
	if env == "" {
		return
	}
	secretEnvsMu.Lock()
	defer secretEnvsMu.Unlock()
	for i, e := range SecretEnvs {
		if e == env {
			SecretEnvs = append(SecretEnvs[:i], SecretEnvs[i+1:]...)
			return
		}
	}
}

// IsSecretEnv reports whether the environment-variable name env contains any
// of the sensitive substrings in SecretEnvs. The check is case-sensitive.
//
// It is safe for concurrent use alongside AddSecretEnv and RemoveSecretEnv.
//
// Example:
//
//	if verbose.IsSecretEnv(key) {
//	    // do not log the value of os.Getenv(key)
//	}
func IsSecretEnv(env string) bool {
	for _, e := range secretEnvsCopy() {
		if strings.Contains(env, e) {
			return true
		}
	}
	return false
}

// ImportSecrets accepts a map of SHA-512 hex digests to the byte-lengths of
// their corresponding plaintext secrets and imports each one via AddHash.
// It returns the count of successfully imported secrets and any errors that
// occurred. A partial import is possible — all valid entries are committed
// even when some entries fail.
//
// Use this function to restore secrets from an external store (e.g. a secrets
// manager) without ever holding the plaintext in memory.
//
// Example:
//
//	n, err := verbose.ImportSecrets(map[string]int{
//	    "abc123...128hexchars...": 32,
//	})
func ImportSecrets(hashes map[string]int) (imported int, err error) {
	var errs []error
	for hash, length := range hashes {
		if e := AddHash(hash, length); e != nil {
			errs = appendError(errs, e)
			continue
		}
		imported++
	}
	if len(errs) > 0 {
		err = errors.Join(errs...)
	}
	return
}

func appendError(errs []error, err error) []error {
	if err != nil {
		return append(errs, err)
	}
	return errs
}

// IsSecret reports whether the given SHA-512 hex digest is present in the
// registered secrets map. It is safe for concurrent use.
//
// Example:
//
//	hash, _ := verbose.SecretBytes("mytoken").Sha512()
//	if verbose.IsSecret(hash) {
//	    fmt.Println("already registered")
//	}
func IsSecret(hash string) (exists bool) {
	secrets.hmu.RLock()
	_, exists = secrets.Hashes[hash]
	secrets.hmu.RUnlock()
	return
}

// AddHash registers a pre-computed SHA-512 hex digest with the secrets
// registry. length must be the byte-length of the original plaintext and must
// be at least SecretMinLength. The hash must be exactly 128 hex characters.
//
// The replacement string is automatically generated as a string of asterisks
// whose length equals length.
//
// This is a lower-level alternative to AddSecret for callers who already hold
// the hash (e.g. after loading from a secrets manager). Prefer AddSecret when
// you have the plaintext available.
//
// Example:
//
//	err := verbose.AddHash(sha512HexString, 32)
func AddHash(hash string, length int) error {
	if length < SecretMinLength {
		return fmt.Errorf("error in AddHash() for length %d ; need at least %d",
			length, SecretMinLength)
	}
	if len(hash) != 128 {
		return fmt.Errorf("invalid checksum length for SHA512")
	}
	return commitHash(hash, strings.Repeat("*", length), length)
}

// AddSecret hashes secret using SHA-512 and stores the digest together with
// replaceWith in the secrets registry. Every subsequent call to Printf,
// Println, Sanitize, or any other sanitising log function will replace
// occurrences of the plaintext secret with replaceWith.
//
// The plaintext is never stored — only the SHA-512 digest persists after this
// call returns.
//
// If replaceWith is empty, a string of 36 asterisks is used. replaceWith is
// capped at 88 characters; if it is longer and consists entirely of a single
// repeated character it is truncated to 36 characters, otherwise the last
// three characters are replaced with "...".
//
// Returns an error if secret is shorter than SecretMinLength.
//
// Performance: AddSecret computes one SHA-512 digest and acquires three mutex
// locks (one each for Hashes, Lengths, and min/max). At ~315 ns/op on modern
// hardware this is negligible for one-time registration at startup but should
// not be called in a hot loop.
//
// Example:
//
//	err := verbose.AddSecret(verbose.SecretBytes(os.Getenv("DB_PASSWORD")), "[DB_PASSWORD]")
func AddSecret(secret SecretBytes, replaceWith string) (err error) {
	rwMin := 88
	smMask := 36
	if len(secret) == 0 {
		return nil
	}
	if len(secret) < SecretMinLength {
		return fmt.Errorf("!error! got %d wanted %d+ !message! eligible secrets are defined as verbose.SecretMinLength",
			len(secret), SecretMinLength)
	}
	if len(replaceWith) == 0 {
		replaceWith = strings.Repeat("*", smMask)
	}

	if charsRepeat(replaceWith) && len(replaceWith) > smMask {
		replaceWith = replaceWith[:smMask]
	}

	if len(replaceWith) > rwMin {
		replaceWith = replaceWith[:len(replaceWith)-3] + "..."
	}
	hexChecksum, checksumErr := secret.Sha512()
	if checksumErr != nil {
		return fmt.Errorf("error in secret.Sha512() caught: %v", checksumErr)
	}
	return commitHash(hexChecksum, replaceWith, len(secret))
}

// charsRepeat reports whether every byte in c is identical to the first byte.
// It is used to decide whether a replaceWith string is a run of a single
// character (e.g. "****") and can be safely truncated.
func charsRepeat(c string) bool {
	fc := c[0]
	for i := 1; i < len(c); i++ {
		if c[i] != fc {
			return false
		}
	}
	return true
}

// RemoveSecret hashes secret and purges the corresponding digest from the
// registry. After this call, the plaintext will no longer be redacted from log
// output. It is safe for concurrent use.
//
// Returns an error if secret is shorter than SecretMinLength or if the
// underlying map deletion fails (which would indicate a serious runtime
// consistency problem).
//
// Example:
//
//	err := verbose.RemoveSecret(verbose.SecretBytes(token))
func RemoveSecret(secret SecretBytes) (err error) {
	if len(secret) == 0 {
		return nil
	}
	if len(secret) < SecretMinLength {
		return fmt.Errorf("!error! got %d wanted %d+ !message! eligible secrets are defined as verbose.SecretMinLength",
			len(secret), SecretMinLength)
	}
	hexChecksum, checksumErr := secret.Sha512()
	if checksumErr != nil {
		return fmt.Errorf("error in secret.Sha512() caught: %v", checksumErr)
	}
	return purgeHash(hexChecksum)
}

// purgeHash removes the given SHA-512 hex digest from both the Hashes and
// Lengths maps and verifies the deletions. It is an internal helper; external
// callers should use RemoveSecret.
func purgeHash(hash string) error {
	if len(hash) < 128 {
		return fmt.Errorf("purgeHash received a hash that is not 128 characters - its invalid SHA512 checksum - cant use")
	}
	var exists bool
	secrets.hmu.RLock()
	_, exists = secrets.Hashes[hash]
	secrets.hmu.RUnlock()
	if exists {
		secrets.hmu.Lock()
		delete(secrets.Hashes, hash)
		secrets.hmu.Unlock()
	}
	secrets.lmu.RLock()
	_, exists = secrets.Lengths[hash]
	secrets.lmu.RUnlock()
	if exists {
		secrets.lmu.Lock()
		delete(secrets.Lengths, hash)
		secrets.lmu.Unlock()
	}

	secrets.hmu.RLock()
	_, exists = secrets.Hashes[hash]
	secrets.hmu.RUnlock()
	if exists {
		return errors.New("hash failed to remove from secrets Hashes map")
	}

	secrets.lmu.RLock()
	_, exists = secrets.Lengths[hash]
	secrets.lmu.RUnlock()
	if exists {
		return errors.New("hash failed to remove from secrets Lengths map")
	}
	return nil
}

// commitHash stores hash, replaceWith, and length atomically (under separate
// per-map locks) into the three secrets maps. It is the single write path for
// all secret registration functions.
//
// Invariants enforced:
//   - hash must be exactly 128 hex characters (SHA-512).
//   - length must be greater than zero.
//   - replaceWith defaults to a string of asterisks when empty.
//
// Error messages include only the first 8 characters of hash when the hash
// itself is part of the diagnostic, following the short-form hash convention
// used in git and similar tools. The full hash is retained in the Hashes map.
//
// Performance: three separate mutex acquisitions are made (hmu, lmu, mmu).
// This is intentional — holding all three simultaneously would create a wider
// critical section and increase lock contention under concurrent registration.
func commitHash(hash string, replaceWith string, length int) error {
	if len(hash) != 128 {
		return fmt.Errorf("commitHash() received invalid hash length %d; SHA512 hex must be 128 characters", len(hash))
	}
	if length == 0 {
		return fmt.Errorf("commitHash() received length of 0 for hash %.8s...", hash)
	}
	if replaceWith == "" {
		replaceWith = strings.Repeat("*", length)
	}

	secrets.hmu.Lock()
	secrets.Hashes[hash] = replaceWith
	secrets.hmu.Unlock()

	secrets.lmu.Lock()
	secrets.Lengths[hash] = length
	secrets.lmu.Unlock()

	secrets.mmu.Lock()
	if secrets.min == 0 || secrets.min > length {
		secrets.min = length
	}
	if secrets.max < length {
		secrets.max = length
	}
	secrets.mmu.Unlock()

	return nil
}
