package verbose

import (
	"strings"
	"sync"
	"testing"
)

// TestSetKeyConcurrent verifies that concurrent calls to SetKey do not
// introduce data races on the encryptionKey variable. It does NOT assert that
// Encrypt/Decrypt round-trips succeed when SetKey is called concurrently with
// them, because that scenario is explicitly outside the supported usage of
// SetKey: the function is intended to be called once at program startup before
// any encryption or decryption takes place.
//
// What this test guarantees:
//   - No panic occurs when SetKey, EncryptUsingKey, and DecryptUsingKey are
//     called from multiple goroutines simultaneously.
//   - The race detector reports no data races.
func TestSetKeyConcurrent(t *testing.T) {
	validKeys := []string{
		strings.Repeat("a", 16),
		strings.Repeat("b", 24),
		strings.Repeat("c", 32),
	}

	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := validKeys[i%len(validKeys)]
			if err := SetKey(key); err != nil {
				t.Errorf("SetKey() error = %v", err)
			}
		}(i)
	}

	// Use EncryptUsingKey/DecryptUsingKey with a fixed local key so the
	// round-trip is fully isolated from the concurrent SetKey calls above.
	// Using the package-level Encrypt/Decrypt here would produce legitimate
	// AES-GCM authentication failures whenever SetKey changes the global key
	// between the encrypt and decrypt calls — that is correct behaviour, not
	// a bug, and is not what this test is measuring.
	fixedKey := SecureBytes(strings.Repeat("z", 32))
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := SecureBytes("test data")
			if _, err := data.EncryptUsingKey(fixedKey); err != nil {
				t.Errorf("EncryptUsingKey() error = %v", err)
				return
			}
			if _, err := data.DecryptUsingKey(fixedKey); err != nil {
				t.Errorf("DecryptUsingKey() error = %v", err)
			}
		}()
	}

	wg.Wait()
}

func TestSetKeyInvalidLength(t *testing.T) {
	tests := []struct {
		key     string
		wantErr bool
	}{
		{strings.Repeat("a", 15), true},
		{strings.Repeat("a", 16), false},
		{strings.Repeat("a", 24), false},
		{strings.Repeat("a", 32), false},
		{strings.Repeat("a", 33), true},
		{"", true},
	}
	for _, tt := range tests {
		if err := SetKey(tt.key); (err != nil) != tt.wantErr {
			t.Errorf("SetKey(%d bytes) error = %v, wantErr %v", len(tt.key), err, tt.wantErr)
		}
	}
}

// TestGenerateEncryptionKey verifies that GenerateEncryptionKey returns a
// non-empty key of exactly keyLength bytes.
func TestGenerateEncryptionKey(t *testing.T) {
	key := GenerateEncryptionKey(0)
	if len(key) == 0 {
		t.Error("Expected encryption key to be generated, but got an empty string")
	}
	if len(key) != keyLength {
		t.Errorf("Expected encryption key length to be %d, but got %d", keyLength, len(key))
	}
}

// TestEncrypt verifies that Encrypt produces non-empty ciphertext that differs
// from the original plaintext and marks the value as encrypted.
func TestEncrypt(t *testing.T) {
	originalMessage := "Test data"
	originalData := SecureBytes(originalMessage)
	encryptedData, err := originalData.Encrypt()

	if err != nil {
		t.Errorf("Expected no error during encryption, but got: %v", err)
	}
	if encryptedData == "" {
		t.Error("Expected encrypted data to be non-empty, but got an empty string")
	}
	if strings.EqualFold(originalMessage, encryptedData) {
		t.Error("Expected encrypted data to differ from original data, but they are the same")
	}
	if !originalData.IsEncrypted() {
		t.Error("Expected data to be marked as encrypted, but it is not")
	}
}

// TestDecrypt verifies that a round-trip Encrypt → Decrypt recovers the
// original plaintext and clears the encrypted flag.
func TestDecrypt(t *testing.T) {
	originalData := SecureBytes("Test data")
	_, err := originalData.Encrypt()
	if err != nil {
		t.Errorf("Expected no error during encryption, but got: %v", err)
	}

	decryptedData, err := originalData.Decrypt()
	if err != nil {
		t.Errorf("Expected no error during decryption, but got: %v", err)
	}
	if decryptedData != "Test data" {
		t.Errorf("Expected decrypted data to match original data, but got: %s", decryptedData)
	}
	if originalData.IsEncrypted() {
		t.Error("Expected data to be marked as not encrypted after decryption, but it is still marked as encrypted")
	}
}

// TestIsEncrypted verifies that IsEncrypted reflects the correct state before
// and after encryption.
func TestIsEncrypted(t *testing.T) {
	originalData := SecureBytes("Test data")
	if originalData.IsEncrypted() {
		t.Error("Expected data to be marked as not encrypted initially, but it is marked as encrypted")
	}

	_, err := originalData.Encrypt()
	if err != nil {
		t.Errorf("Expected no error during encryption, but got: %v", err)
	}
	if !originalData.IsEncrypted() {
		t.Error("Expected data to be marked as encrypted after encryption, but it is not")
	}
}

// TestEncryptAlreadyEncrypted verifies that calling Encrypt on already-
// encrypted data returns an error rather than double-encrypting.
func TestEncryptAlreadyEncrypted(t *testing.T) {
	originalData := SecureBytes("Test data")
	_, err := originalData.Encrypt()
	if err != nil {
		t.Errorf("Expected no error during first encryption, but got: %v", err)
	}

	_, err = originalData.Encrypt()
	if err == nil {
		t.Error("Expected an error when encrypting already encrypted data, but got none")
	}
}

// TestDecryptNotEncrypted verifies that calling Decrypt on plaintext returns
// the original string without error and leaves IsEncrypted false.
func TestDecryptNotEncrypted(t *testing.T) {
	originalData := SecureBytes("Test data")
	decryptedData, err := originalData.Decrypt()

	if err != nil {
		t.Errorf("Expected no error during decryption, but got: %v", err)
	}
	if decryptedData != "Test data" {
		t.Errorf("Expected decrypted data to match original data, but got: %s", decryptedData)
	}
	if originalData.IsEncrypted() {
		t.Error("Expected data to be marked as not encrypted, but it is marked as encrypted")
	}
}
