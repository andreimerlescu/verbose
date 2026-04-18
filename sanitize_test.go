package verbose

import (
	"fmt"
	"strings"
	"testing"
)

var testSecrets = []struct {
	length      int
	replaceWith string
}{
	{5, "[REDACTED_5]"},
	{10, "[REDACTED_10]"},
	{20, "[REDACTED_20]"},
	{40, "[REDACTED_40]"},
	{80, "[REDACTED_80]"},
	{160, "[REDACTED_160]"},
	{420, "[REDACTED_420]"},
}

var inputLengths = []int{0, 10, 20, 40, 80, 160, 320, 640, 1280, 2560}

func BenchmarkSanitize(b *testing.B) {
	for _, inputLen := range inputLengths {
		for _, secret := range testSecrets {
			b.Run(fmt.Sprintf("sanitizeInput/%dBytes/%dSecretBytes", inputLen, secret.length), func(b *testing.B) {
				input := strings.Repeat("a", inputLen)
				for i := 0; i < secret.length; i++ {
					thisSecret := strings.Repeat(fmt.Sprintf("secret%d", i), secret.length/7)
					replaceWith := fmt.Sprintf("[REDACTED_%d]", len(thisSecret))
					if err := AddSecret(SecretBytes(thisSecret), replaceWith); err != nil {
						b.Fatalf("Failed to add secret: %v", err)
					}
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_ = sanitizeInput(input)
				}
			})
		}
	}
}

func BenchmarkSanitizeNoSecrets(b *testing.B) {
	for _, inputLen := range inputLengths {
		b.Run(fmt.Sprintf("sanitizeInput/%dBytes/NoSecrets", inputLen), func(b *testing.B) {
			input := strings.Repeat("a", inputLen)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = sanitizeInput(input)
			}
		})
	}
}

func TestSanitizeOverlappingSecrets(t *testing.T) {
    // reset secrets state
    secrets = NewSecrets()

    // "supersecret" contains "secret" — overlapping substrings
    outer := SecretBytes("supersecret")
    inner := SecretBytes("secret")

    if err := AddSecret(outer, "[OUTER]"); err != nil {
        t.Fatalf("AddSecret outer: %v", err)
    }
    if err := AddSecret(inner, "[INNER]"); err != nil {
        t.Fatalf("AddSecret inner: %v", err)
    }

    input := "login supersecret end"
    got := sanitizeInput(input)

    // should not contain either raw value
    if strings.Contains(got, "supersecret") || strings.Contains(got, "secret") {
        t.Errorf("sanitizeInput did not redact overlapping secrets, got: %q", got)
    }
    // should not contain corrupt offset artifacts
    if strings.Contains(got, "super[INNER]") {
        t.Errorf("sanitizeInput produced corrupt output from overlap, got: %q", got)
    }
}

