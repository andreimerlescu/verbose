package verbose

import (
	"testing"
	"unicode/utf8"
)

// FuzzScrub verifies that Scrub never panics on arbitrary input and always
// returns valid UTF-8.
func FuzzScrub(f *testing.F) {
	// seed corpus — known interesting inputs
	f.Add("normal log line")
	f.Add("")
	f.Add("-----BEGIN RSA PRIVATE KEY-----\nfakekey\n-----END RSA PRIVATE KEY-----")
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.somepayload")
	f.Add("ghp_faketoken\"")
	f.Add("\x00\x01\x02")
	f.Add(string([]byte{0xff, 0xfe}))
	f.Add("BEGIN_CUSTOM_SECRETsecretvalueEND_CUSTOM_SECRET")

	f.Fuzz(func(t *testing.T, input string) {
		result := Scrub(input)

		// Scrub must never return invalid UTF-8 if given valid UTF-8
		if utf8.ValidString(input) && !utf8.ValidString(result) {
			t.Errorf("Scrub produced invalid UTF-8 from valid UTF-8 input: %q -> %q", input, result)
		}

		// result must never be longer than input + len("[CLEANED]") overhead
		// (cleaning can only shrink or replace, never grow unboundedly)
		if len(result) > len(input)+len("[CLEANED]")*50 {
			t.Errorf("Scrub output suspiciously large: input len %d, output len %d", len(input), len(result))
		}
	})
}

// FuzzSanitizeInput verifies that sanitizeInput never panics on arbitrary
// input and that registered secrets are always redacted.
func FuzzSanitizeInput(f *testing.F) {
	// register a known secret so the redaction path is exercised
	secret := SecretBytes("fuzzSecret99")
	_ = AddSecret(secret, "[FUZZED]")

	f.Add("normal input")
	f.Add("")
	f.Add("fuzzSecret99")
	f.Add("prefix fuzzSecret99 suffix")
	f.Add("fuzzSecret99fuzzSecret99")
	f.Add("\x00\x01\x02\x03")
	f.Add(string([]byte{0xff, 0xfe, 0xfd}))

	f.Fuzz(func(t *testing.T, input string) {
		result := sanitizeInput(input)

		// the registered secret must never appear in output
		if containsBytes(result, "fuzzSecret99") {
			t.Errorf("sanitizeInput leaked secret in output: %q -> %q", input, result)
		}

		// output must never be longer than input in a way that suggests corruption
		if len(result) > len(input)+len("[FUZZED]")*50 {
			t.Errorf("sanitizeInput output suspiciously large: input len %d, output len %d", len(input), len(result))
		}
	})
}

// FuzzSecretBytesSha512 verifies that Sha512 never panics and always returns
// a 128-character hex string or an error, never both and never neither for
// valid-length input.
func FuzzSecretBytesSha512(f *testing.F) {
	f.Add([]byte("secret1"))
	f.Add([]byte("a longer secret value here"))
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add([]byte("short")) // exactly SecretMinLength

	f.Fuzz(func(t *testing.T, input []byte) {
		sb := SecretBytes(input)
		hash, err := sb.Sha512()

		if err != nil && hash != "" {
			t.Error("Sha512 returned both a hash and an error")
		}
		if err == nil && len(input) >= SecretMinLength && len(hash) != 128 {
			t.Errorf("Sha512 returned non-128-char hash for valid input: len=%d hash=%q", len(hash), hash)
		}
		if err == nil && len(input) < SecretMinLength && len(input) > 0 {
			t.Error("Sha512 should have returned error for input below SecretMinLength")
		}
	})
}

// FuzzEncryptDecrypt verifies that encrypting then decrypting arbitrary input
// always recovers the original plaintext.
func FuzzEncryptDecrypt(f *testing.F) {
	f.Add("hello world")
	f.Add("")
	f.Add("a")
	f.Add(string([]byte{0x00, 0x01, 0x02}))

	f.Fuzz(func(t *testing.T, input string) {
		data := SecureBytes(input)

		encrypted, err := data.Encrypt()
		if err != nil {
			// IsEncrypted inputs are rejected — not a bug
			return
		}
		if encrypted == "" {
			t.Error("Encrypt returned empty string without error")
		}

		decrypted, err := data.Decrypt()
		if err != nil {
			t.Errorf("Decrypt failed after successful Encrypt: %v", err)
			return
		}
		if decrypted != input {
			t.Errorf("round-trip mismatch: input %q, got %q", input, decrypted)
		}
	})
}

// containsBytes is a helper to avoid importing strings in a way that
// could be confused with the sanitized output check.
func containsBytes(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) &&
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}()
}
