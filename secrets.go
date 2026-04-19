package verbose

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Hashes map stores hashed secrets and their replacement strings
type Hashes map[string]string

// Lengths map stores hashes secrets and their original secret string length
type Lengths map[string]int

// Secrets describes hashed secrets and their raw lengths
type Secrets struct {
	Hashes  Hashes
	Lengths Lengths
	min     int
	max     int
	hmu     *sync.RWMutex
	lmu     *sync.RWMutex
	mmu     *sync.RWMutex
}

// Avg returns the average of the Secrets Lengths min and max values. Min/Max are updated everytime AddSecret runs.
func (s *Secrets) Avg() int {
	return (s.min + s.max) / 2
}

// NewSecrets provides a Secret with prepared Secret.Hashes and Secret.Lengths maps
func NewSecrets() *Secrets {
	return &Secrets{
		Hashes:  make(Hashes),
		Lengths: make(Lengths),
		lmu:     &sync.RWMutex{},
		hmu:     &sync.RWMutex{},
		mmu:     &sync.RWMutex{},
	}
}

// secrets stores a package wide *Secret
var secrets = NewSecrets()

var SecretMinLength = 5

// secretEnvs holds the list of environment variable name substrings that
// are considered sensitive. Access is protected by secretEnvsMu.
var (
	secretEnvs = []string{
		"KEY", "TOKEN", "PASSW", "CI_", "AWS_", "OP_", "DO_PAT", "OKTA", "KUBE", "WUZAH",
		"CLOUDFLARE_", "CLOUD_FLARE_", "LASTPASS_", "LAST_PASS_", "KEEPER_", "VAULT",
		"INTERCOM", "RABBITMQ", "MAILGUN", "TWILIO", "ZENDESK", "SENDGRID", "AUTH0",
		"JENKINS", "GITLAB", "GITHUB", "GH", "GITEA", "DATADOG", "SENTRY", "PAGERDUTY",
		"ROLLBAR", "SLACK", "REDIS", "SQL", "ROOT", "MONGO", "CERT", "_PEM", "_PK", "PK_",
		"PRIVATE_", "SECRET_", "PROTECTED", "_DSN", "DSN_", "_URI", "URI_",
	}
	secretEnvsMu sync.RWMutex
)

// SecretEnvs returns a copy of the current sensitive environment variable
// name substrings. Callers may not modify the returned slice directly —
// use AddSecretEnv or RemoveSecretEnv to mutate the list.
func SecretEnvs() []string {
	secretEnvsMu.RLock()
	defer secretEnvsMu.RUnlock()
	cp := make([]string, len(secretEnvs))
	copy(cp, secretEnvs)
	return cp
}

// AddSecretEnv appends env to the list of sensitive environment variable
// name substrings if it is not already present. It is safe for concurrent use.
func AddSecretEnv(env string) {
	secretEnvsMu.Lock()
	defer secretEnvsMu.Unlock()
	for _, e := range secretEnvs {
		if e == env {
			return
		}
	}
	secretEnvs = append(secretEnvs, env)
}

// RemoveSecretEnv removes env from the list of sensitive environment variable
// name substrings if present. It is safe for concurrent use.
func RemoveSecretEnv(env string) {
	secretEnvsMu.Lock()
	defer secretEnvsMu.Unlock()
	for i, e := range secretEnvs {
		if e == env {
			secretEnvs = append(secretEnvs[:i], secretEnvs[i+1:]...)
			return
		}
	}
}

// IsSecretEnv reports whether env contains any of the sensitive environment
// variable name substrings. It is safe for concurrent use.
func IsSecretEnv(env string) bool {
	secretEnvsMu.RLock()
	defer secretEnvsMu.RUnlock()
	for _, e := range secretEnvs {
		if strings.Contains(env, e) {
			return true
		}
	}
	return false
}

// ImportSecrets accepts a map of SHA512 hex hashes to their original secret
// lengths and adds each to the secrets map via AddHash. It returns the count
// of successfully imported secrets and any errors encountered. A partial
// import is possible — errors are joined and returned alongside the count of
// successful imports.
func ImportSecrets(hashes map[string]int) (imported int, err error) {
	var errs []error
	for hash, length := range hashes {
		if e := AddHash(hash, length); e != nil {
			errs = appendError(errs, e)
			continue // do not count failures
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

// IsSecret returns true if the hash is in the Hashes map in secrets
func IsSecret(hash string) (exists bool) {
	secrets.hmu.RLock()
	_, exists = secrets.Hashes[hash]
	secrets.hmu.RUnlock()
	return
}

// AddHash accepts the SHA512 hash and the original secret's length
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

// AddSecret hashes the secret and stores it in the Secrets map with the replaceWith value
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

// charsRepeat returns true if c is "aaa" or something like that
func charsRepeat(c string) bool {
	fc := c[0]
	for i := 1; i < len(c); i++ {
		if c[i] != fc {
			return false
		}
	}
	return true
}

// RemoveSecret hashes the secret and removes the hash if it exists in memory from the secrets list
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

// purgeHash deletes the hash from the secrets
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

// commitHash stores the hash and its replacement string and original length
// into the secrets maps under a single lock acquisition per map, preventing
// any TOCTOU race between writing and verifying the write.
//
// Returns an error if hash is not exactly 128 characters (SHA512 hex),
// if length is zero, or if replaceWith is empty after defaulting.
func commitHash(hash string, replaceWith string, length int) error {
	if len(hash) != 128 {
		return fmt.Errorf("commitHash() received invalid hash length %d; SHA512 hex must be 128 characters", len(hash))
	}
	if length == 0 {
		return fmt.Errorf("commitHash() received length of 0 for hash %s", hash)
	}
	if replaceWith == "" {
		replaceWith = strings.Repeat("*", length)
	}

	// Write hash and replaceWith atomically under a single lock — no
	// verification read needed since a map assignment cannot partially fail.
	secrets.hmu.Lock()
	secrets.Hashes[hash] = replaceWith
	secrets.hmu.Unlock()

	// Write length separately under its own lock.
	secrets.lmu.Lock()
	secrets.Lengths[hash] = length
	secrets.lmu.Unlock()

	// Update min/max under a single lock acquisition to prevent a race
	// between reading min/max and writing them.
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
