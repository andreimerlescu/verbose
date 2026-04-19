package verbose

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
)

// TestImportSecretsCount verifies that ImportSecrets only counts
// successfully imported secrets and not failures.
func TestImportSecretsCount(t *testing.T) {
	secrets = NewSecrets()

	// generate two valid SHA512 hashes
	secret1 := SecretBytes("import-secret-one")
	secret2 := SecretBytes("import-secret-two")

	hash1, err := secret1.Sha512()
	if err != nil {
		t.Fatalf("Sha512() error = %v", err)
	}
	hash2, err := secret2.Sha512()
	if err != nil {
		t.Fatalf("Sha512() error = %v", err)
	}

	tests := []struct {
		name         string
		hashes       map[string]int
		wantImported int
		wantErr      bool
	}{
		{
			name: "all valid",
			hashes: map[string]int{
				hash1: len("import-secret-one"),
				hash2: len("import-secret-two"),
			},
			wantImported: 2,
			wantErr:      false,
		},
		{
			name: "all invalid — hash too short",
			hashes: map[string]int{
				"tooshort": 10,
			},
			wantImported: 0,
			wantErr:      true,
		},
		{
			name: "all invalid — length below SecretMinLength",
			hashes: map[string]int{
				strings.Repeat("a", 128): 1,
			},
			wantImported: 0,
			wantErr:      true,
		},
		{
			name: "mixed valid and invalid",
			hashes: map[string]int{
				hash1: len("import-secret-one"),
				"bad": 10, // invalid hash
			},
			wantImported: 1,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets = NewSecrets() // reset between cases
			got, err := ImportSecrets(tt.hashes)
			if (err != nil) != tt.wantErr {
				t.Errorf("ImportSecrets() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.wantImported {
				t.Errorf("ImportSecrets() imported = %d, want %d", got, tt.wantImported)
			}
		})
	}
}

// TestImportSecretsPartialImport verifies that a partial import leaves
// the successfully imported secrets accessible and failed ones absent.
func TestImportSecretsPartialImport(t *testing.T) {
	secrets = NewSecrets()

	secret := SecretBytes("partial-import-secret")
	hash, err := secret.Sha512()
	if err != nil {
		t.Fatalf("Sha512() error = %v", err)
	}

	imported, err := ImportSecrets(map[string]int{
		hash:      len("partial-import-secret"),
		"badhash": 10,
	})
	if err == nil {
		t.Error("ImportSecrets() expected error for bad hash, got nil")
	}
	if imported != 1 {
		t.Errorf("ImportSecrets() imported = %d, want 1", imported)
	}

	// valid hash should still be accessible
	if !IsSecret(hash) {
		t.Error("valid hash should be present in secrets after partial import")
	}
}

// TestCommitHashConcurrent verifies that concurrent calls to commitHash
// do not produce data races or inconsistent state in the secrets maps.
func TestCommitHashConcurrent(t *testing.T) {
	// reset secrets state for a clean test
	secrets = NewSecrets()

	var wg sync.WaitGroup
	hashes := make([]string, 20)

	// generate 20 valid SHA512 hex strings and commit them concurrently
	for i := 0; i < 20; i++ {
		secret := SecretBytes(fmt.Sprintf("concurrent-secret-%d", i))
		hash, err := secret.Sha512()
		if err != nil {
			t.Fatalf("Sha512() error = %v", err)
		}
		hashes[i] = hash
		wg.Add(1)
		go func(h string, idx int) {
			defer wg.Done()
			if err := commitHash(h, fmt.Sprintf("[REDACTED_%d]", idx), idx+SecretMinLength); err != nil {
				t.Errorf("commitHash() error = %v", err)
			}
		}(hash, i)
	}
	wg.Wait()

	// verify all hashes were committed correctly with no gaps
	for i, hash := range hashes {
		secrets.hmu.RLock()
		replaceWith, exists := secrets.Hashes[hash]
		secrets.hmu.RUnlock()
		if !exists {
			t.Errorf("hash %d not found in secrets.Hashes after concurrent commitHash", i)
		}
		expected := fmt.Sprintf("[REDACTED_%d]", i)
		if replaceWith != expected {
			t.Errorf("hash %d replaceWith = %q, want %q", i, replaceWith, expected)
		}

		secrets.lmu.RLock()
		length, lexists := secrets.Lengths[hash]
		secrets.lmu.RUnlock()
		if !lexists {
			t.Errorf("hash %d not found in secrets.Lengths after concurrent commitHash", i)
		}
		if length != i+SecretMinLength {
			t.Errorf("hash %d length = %d, want %d", i, length, i+SecretMinLength)
		}
	}

	// verify min/max are consistent
	secrets.mmu.Lock()
	gotMin := secrets.min
	gotMax := secrets.max
	secrets.mmu.Unlock()

	if gotMin != SecretMinLength {
		t.Errorf("secrets.min = %d, want %d", gotMin, SecretMinLength)
	}
	if gotMax != 19+SecretMinLength {
		t.Errorf("secrets.max = %d, want %d", gotMax, 19+SecretMinLength)
	}
}

// TestCommitHashInvalidInputs verifies that commitHash correctly rejects
// invalid hash lengths and zero lengths.
func TestCommitHashInvalidInputs(t *testing.T) {
	tests := []struct {
		name        string
		hash        string
		replaceWith string
		length      int
		wantErr     bool
	}{
		{
			name:        "invalid hash length",
			hash:        strings.Repeat("a", 64), // SHA256 length, not SHA512
			replaceWith: "[REDACTED]",
			length:      10,
			wantErr:     true,
		},
		{
			name:        "zero length",
			hash:        strings.Repeat("a", 128),
			replaceWith: "[REDACTED]",
			length:      0,
			wantErr:     true,
		},
		{
			name:        "empty replaceWith defaults to asterisks",
			hash:        strings.Repeat("a", 128),
			replaceWith: "",
			length:      10,
			wantErr:     false,
		},
		{
			name:        "valid inputs",
			hash:        strings.Repeat("b", 128),
			replaceWith: "[REDACTED]",
			length:      10,
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := commitHash(tt.hash, tt.replaceWith, tt.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("commitHash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func BenchmarkAddSecret(b *testing.B) {
	b.Run("AddSecret", func(b *testing.B) {
		input := strings.Repeat("a", 14)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = AddSecret(SecretBytes(input), "")
		}
	})
}

func BenchmarkRemoveSecret(b *testing.B) {
	b.Run("RemoveSecret", func(b *testing.B) {
		input := strings.Repeat("a", 14)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = RemoveSecret(SecretBytes(input))
		}
	})
}

func TestRemoveSecret(t *testing.T) {
	var err error
	fakeSecrets := []string{"secret1", "secret2", "secret3", "secret4", "secret5"}
	for _, fakeSecret := range fakeSecrets {
		err = AddSecret(SecretBytes(fakeSecret), "")
		if err != nil {
			t.Errorf("AddSecret() error = %v", err)
		}
	}
	slices.Reverse(fakeSecrets)
	for _, fakeSecret := range fakeSecrets {
		err = RemoveSecret(SecretBytes(fakeSecret))
		if err != nil {
			t.Errorf("AddSecret() error = %v", err)
		}
	}
}

func TestIsSecretEnv(t *testing.T) {

}

func TestAddSecret(t *testing.T) {
	type args struct {
		secret      SecretBytes
		replaceWith string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "cant add secret",
			args: args{
				secret:      SecretBytes("abc"),
				replaceWith: "",
			},
			wantErr: true,
		},
		{
			name: "add secret",
			args: args{
				secret:      SecretBytes("secret1"),
				replaceWith: "",
			},
			wantErr: false,
		},
		{
			name: "add another secret",
			args: args{
				secret:      SecretBytes("secret123"),
				replaceWith: "",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := AddSecret(tt.args.secret, tt.args.replaceWith); (err != nil) != tt.wantErr {
				t.Errorf("AddSecret() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
