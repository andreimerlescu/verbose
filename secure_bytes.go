package verbose

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// SecureBytes is a type that wraps a byte slice with encryption and decryption capabilities
type SecureBytes []byte

const (
	keyLength    = 32 // max for AES-GCM
	uppercase    = "ABCDEGHKMOPQRSTVWXYZ"
	lowercase    = "abcdeghkmopqrstvwxyz"
	digits       = "0123456789"
	specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
)

// GenerateEncryptionKey generates a random password with the given length (2 tries allowed)
func GenerateEncryptionKey(tries int) SecureBytes {
	tries++
	if tries > 3 {
		return SecureBytes{}
	}
	charset := uppercase + lowercase + digits + specialChars
	password := make([]byte, keyLength)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := range password {
		randomIndex, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return GenerateEncryptionKey(tries)
		}
		password[i] = charset[randomIndex.Int64()]
	}

	return SecureBytes(password)
}

// encryptionKey is used for using SecureBytes.Encrypt and SecureBytes.Decrypt
var encryptionKey = GenerateEncryptionKey(0)

// SetKey updates the encryptionKey with newKey
func SetKey(newKey string) error {
	l := len(newKey)
	validKey := false
	if l == 16 || l == 24 || l == 32 {
		validKey = true
	}
	if validKey {
		encryptionKey = SecureBytes(newKey)
		return nil
	} else {
		return fmt.Errorf("invalid key length: expected 16, 24, or 32, got %d", l)
	}
}

// prefix is used in determining if data is encrypted
const prefix = "ENC:"

// Encrypt encrypts the SecureBytes and returns the base64 encoded string and error if any
func (sb *SecureBytes) Encrypt() (string, error) {
	return sb.EncryptUsingKey(encryptionKey)
}

// EncryptUsingKey uses a custom key for encrypting/decrypting
func (sb *SecureBytes) EncryptUsingKey(key SecureBytes) (string, error) {
	if sb.IsEncrypted() {
		return "", errors.New("data is already encrypted")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, *sb, nil)
	encryptedData := prefix + base64.StdEncoding.EncodeToString(ciphertext)
	*sb = SecureBytes(encryptedData)
	return encryptedData, nil
}

// Decrypt decrypts the SecureBytes if it is encrypted and returns the plain text string and error if any
func (sb *SecureBytes) Decrypt() (string, error) {
	return sb.DecryptUsingKey(encryptionKey)
}

// DecryptUsingKey uses another key for encrypting/decrypting
func (sb *SecureBytes) DecryptUsingKey(key SecureBytes) (string, error) {
	if !sb.IsEncrypted() {
		return string(*sb), nil
	}
	encodedData := string(*sb)[len(prefix):]
	ciphertext, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}
	*sb = plaintext
	return string(plaintext), nil
}

// IsEncrypted checks if the SecureBytes are encrypted by looking for the specific prefix
func (sb *SecureBytes) IsEncrypted() bool {
	return bytes.HasPrefix(*sb, []byte(prefix))
}
