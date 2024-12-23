package verbose

import (
	"testing"
)

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
