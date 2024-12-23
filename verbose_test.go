package verbose

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerboseLogging(t *testing.T) {
	// Create a temporary directory for logging
	tempDir, err := os.MkdirTemp("", "verbose_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir) // Step 8: Clean up the temp directory after the test

	// Set the log directory to the temp directory
	Dir = tempDir

	// Initialize the verbose vLogr
	err = NewLogger(Options{})
	if err != nil {
		t.Fatalf("Failed to initialize verbose vLogr: %v", err)
	}

	// Add a secret to the Secrets map
	secret := "mysecret"
	replaceWith := "[REDACTED]"
	err = AddSecret(SecretBytes(secret), replaceWith)
	if err != nil {
		t.Fatalf("Failed to add secret: %v", err)
	}

	// Log a line containing the secret
	logMessageWithSecret := fmt.Sprintf("This is a secret: %s", secret)
	Printf("message with secret = %s", logMessageWithSecret)

	// Read the log file
	logFilePath := filepath.Join(tempDir, "verbose.log")
	logData, err := os.ReadFile(logFilePath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	// Verify the vLogr does not contain the secret
	logContent := string(logData)
	if strings.Contains(logContent, secret) {
		t.Fatalf("The log contains the secret! Log content: %s", logContent)
	}
	if !strings.Contains(logContent, replaceWith) {
		t.Fatalf("The log does not contain the replacement text! Log content: %s", logContent)
	}

	// Verify the secret is stored as a SHA-512 hash only
	hash := sha512.Sum512([]byte(secret))
	secretHash := hex.EncodeToString(hash[:])
	if _, exists := secrets.Hashes[secretHash]; !exists {
		t.Fatalf("The secret hash is not stored in the map!")
	}
	if secrets.Hashes[secretHash] != replaceWith {
		t.Fatalf("The replacement value is incorrect in the Secrets map!")
	}

	err = RemoveSecret(SecretBytes(secret))
	if err != nil {
		t.Fatalf("Failed to remove secret: %v", err)
	}

	// Log the line that contains the removed secret
	Println("secret has been removed now = " + logMessageWithSecret)

	// Log a line that does not contain a secret
	nonSecretMessage := "This is a public message"
	Println("no secret in this line = " + nonSecretMessage)

	// Read the log file again
	logData, err = os.ReadFile(logFilePath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent = string(logData)
	if !strings.Contains(logContent, nonSecretMessage) {
		t.Fatalf("The log does not contain the non-secret message! Log content: %s", logContent)
	}

	if !strings.Contains(logContent, secret) {
		t.Fatalf("The secret appaears to have not been removed. No secret printed in log file. Content: %s", logContent)
	}
}
