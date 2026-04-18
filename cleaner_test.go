package verbose

import (
	"testing"
)

// TestSecretEnvsConcurrent verifies that concurrent calls to AddSecretEnv,
// RemoveSecretEnv, and IsSecretEnv do not produce data races.
func TestSecretEnvsConcurrent(t *testing.T) {
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(3)
		env := fmt.Sprintf("TEST_ENV_%d", i)

		go func(e string) {
			defer wg.Done()
			AddSecretEnv(e)
		}(env)

		go func(e string) {
			defer wg.Done()
			RemoveSecretEnv(e)
		}(env)

		go func(e string) {
			defer wg.Done()
			_ = IsSecretEnv(e)
		}(env)
	}
	wg.Wait()
}

// TestAddSecretEnvNoDuplicates verifies that AddSecretEnv does not add
// duplicate entries to the secretEnvs slice.
func TestAddSecretEnvNoDuplicates(t *testing.T) {
	initial := len(SecretEnvs())
	AddSecretEnv("MYTOKEN")
	AddSecretEnv("MYTOKEN")
	AddSecretEnv("MYTOKEN")
	if got := len(SecretEnvs()); got != initial+1 {
		t.Errorf("SecretEnvs() len = %d, want %d after duplicate adds", got, initial+1)
	}
	RemoveSecretEnv("MYTOKEN")
}

// TestRemoveSecretEnv verifies that RemoveSecretEnv correctly removes
// an entry and that IsSecretEnv no longer matches it afterward.
func TestRemoveSecretEnv(t *testing.T) {
	AddSecretEnv("UNIQUETOKEN")
	if !IsSecretEnv("MY_UNIQUETOKEN_VALUE") {
		t.Error("expected IsSecretEnv to return true after AddSecretEnv")
	}
	RemoveSecretEnv("UNIQUETOKEN")
	if IsSecretEnv("MY_UNIQUETOKEN_VALUE") {
		t.Error("expected IsSecretEnv to return false after RemoveSecretEnv")
	}
}

// TestKeyTypesConcurrent verifies that concurrent calls to AddKeyType,
// RemoveKeyType, and Scrub do not produce data races.
func TestKeyTypesConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		kt := KeyType{
			Opening: fmt.Sprintf("BEGIN_TEST_%d", i),
			Closing: fmt.Sprintf("END_TEST_%d", i),
		}
		go func(k KeyType) {
			defer wg.Done()
			AddKeyType(k)
		}(kt)

		go func(k KeyType) {
			defer wg.Done()
			RemoveKeyType(k)
		}(kt)

		go func() {
			defer wg.Done()
			_ = Scrub("some input with BEGIN_TEST_0 content END_TEST_0")
		}()
	}
	wg.Wait()
}

// TestAddKeyType verifies that a custom KeyType added via AddKeyType
// is subsequently cleaned by Scrub.
func TestAddKeyType(t *testing.T) {
	kt := KeyType{
		Opening: "BEGIN_CUSTOM_SECRET",
		Closing: "END_CUSTOM_SECRET",
	}
	AddKeyType(kt)
	defer RemoveKeyType(kt)

	input := "some text BEGIN_CUSTOM_SECRETmy secret valueEND_CUSTOM_SECRET more text"
	got := Scrub(input)
	if strings.Contains(got, "my secret value") {
		t.Errorf("Scrub() did not clean custom KeyType, got: %q", got)
	}
	if !strings.Contains(got, "[CLEANED]") {
		t.Errorf("Scrub() expected [CLEANED] in output, got: %q", got)
	}
}

func TestCleaner(t *testing.T) {
	tests := []struct {
		input          string
		expectedOutput string
		expectError    bool
	}{
		{
			input:          "Some regular text with no secrets.",
			expectedOutput: "Some regular text with no secrets.",
			expectError:    false,
		},
		{
			input: `-----BEGIN PGP MESSAGE-----
Version: GnuPG v1
hQEMA0n5Jk4B+eEBARAAszWqXElZ+QK/0T9F...qS38R5x4jA5YcpOCpLe9Jgn1bTz3FpHw
-----END PGP MESSAGE-----`,
			expectedOutput: "[CLEANED]",
			expectError:    false,
		},
		{
    		input: "First JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.firsttoken\nSecond JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secondtoken\n",
    		expectedOutput: "First JWT: [CLEANED]\nSecond JWT: [CLEANED]\n",
    		expectError:    false,
		},
		{
			input:          "Some text with a JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sometoken...\n",
			expectedOutput: "Some text with a JWT token: [CLEANED]\n",
			expectError:    false,
		},
		{
			input:          "DOCKER_AUTH_CONFIG={\"auths\":{\"https://index.docker.io/v1/\":{\"auth\":\"dGVzdDp0ZXN0\"}}}\n",
			expectedOutput: "DOCKER_AUTH_CONFIG=[CLEANED]\n",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		output := Scrub(tt.input)
		if output != tt.expectedOutput {
			t.Errorf("Scrub(%q) = %q; want %q", tt.input, output, tt.expectedOutput)
		}
	}
}
