package verbose

import (
	"strings"
	"sync"
	"testing"
)

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

	// concurrent reads via Encrypt/Decrypt while SetKey is running
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := SecureBytes("test data")
			_, err := data.Encrypt()
			if err != nil {
				return // already encrypted is fine
			}
			_, _ = data.Decrypt()
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

// TestGenerateEncryptionKey tests the GenerateEncryptionKey function
func TestGenerateEncryptionKey(t *testing.T) {
	key := GenerateEncryptionKey(0)
	if len(key) == 0 {
		t.Error("Expected encryption key to be generated, but got an empty string")
	}
	if len(key) != keyLength {
		t.Errorf("Expected encryption key length to be %d, but got %d", keyLength, len(key))
	}
}

// TestEncrypt tests the Encrypt method of SecureBytes
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

// TestDecrypt tests the Decrypt method of SecureBytes
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

// TestIsEncrypted tests the IsEncrypted method of SecureBytes
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

// TestEncryptAlreadyEncrypted tests that attempting to encrypt already encrypted data returns an error
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

// TestDecryptNotEncrypted tests that attempting to decrypt non-encrypted data returns the original string
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
