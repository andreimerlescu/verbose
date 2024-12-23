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

// SecretEnvs defines a list of common ENV names that usually contain secrets, since this program will inherit
// all user.User os.Environ, Secrets are expected to be there, and the vLogr should never expose those secrets due
// to this application printing to logs anything in the os.Environ response or the data.Environ map of os.Environ
var SecretEnvs = []string{
	"KEY", "TOKEN", "PASSW", "CI_", "AWS_", "OP_", "DO_PAT", "OKTA", "KUBE", "WUZAH",
	"CLOUDFLARE_", "CLOUD_FLARE_", "LASTPASS_", "LAST_PASS_", "KEEPER_", "VAULT",
	"INTERCOM", "RABBITMQ", "MAILGUN", "TWILIO", "ZENDESK", "SENDGRID", "AUTH0",
	"JENKINS", "GITLAB", "GITHUB", "GH", "GITEA", "DATADOG", "SENTRY", "PAGERDUTY",
	"ROLLBAR", "SLACK", "REDIS", "SQL", "ROOT", "MONGO", "CERT", "_PEM", "_PK", "PK_",
	"PRIVATE_", "SECRET_", "PROTECTED", "_DSN", "DSN_", "_URI", "URI_",
}

func ImportSecrets(hashes map[string]int) (imported int, err error) {
	var errs []error
	for hash, length := range hashes {
		e := AddHash(hash, length)
		if e != nil {
			errs = appendError(errs, e)
		}
		imported++
	}
	if len(errs) > 0 {
		err = errors.Join(errs...)
		return
	}
	return
}

func appendError(errs []error, err error) []error {
	if err != nil {
		return append(errs, err)
	}
	return errs
}

// IsSecretEnv uses strings.Contains on SecretEnvs against the env string
func IsSecretEnv(env string) bool {
	for _, e := range SecretEnvs {
		if strings.Contains(env, e) {
			return true
		}
	}
	return false
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

// commitHash adds the hash to the secrets in the Hashes map
func commitHash(hash string, replaceWith string, length int) error {
	if len(hash) != 128 {
		return fmt.Errorf("error in commitHash() for length %d ; need at least %d", length, SecretMinLength)
	}
	if length == 0 {
		return fmt.Errorf("error in commitHash() for length 0")
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
	if secrets.min > length {
		secrets.min = length
	}
	if secrets.max < length {
		secrets.max = length
	}
	secrets.mmu.Unlock()

	secrets.hmu.RLock()
	_, exists := secrets.Hashes[hash]
	secrets.hmu.RUnlock()

	if exists {
		return nil
	}

	return fmt.Errorf("hash not committed")
}
