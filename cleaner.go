package verbose

import (
	"fmt"
	"regexp"
	"strings"
)

// KeyType holds the opening and closing markers for different types of keys.
type KeyType struct {
	Opening string
	Closing string
}

// Regular expressions for cleaning yum output
var (
	LastMetadataCheckRegex    = regexp.MustCompile(`(?m)^Last metadata expiration check:.*\n`)
	DependenciesResolvedRegex = regexp.MustCompile(`(?m)^Dependencies resolved\.\n=+\n.*\n=+\n`)
	TransactionSummaryRegex   = regexp.MustCompile(`(?m)^Transaction Summary\n=+\n.*\n\n`)
	RunningTransactionRegex   = regexp.MustCompile(`(?m)^Running transaction\n(?:.*\n)+^Complete!\n`)
	PackageDetailsRegex       = regexp.MustCompile(`(?m)^Installing:\n(?:.*\n)+^Complete!\n`)
	VerifyingRegex            = regexp.MustCompile(`(?m)^\s*Verifying\s*:.*\n(?:.*\n)*?`)
	TrimNewlinesRegex         = regexp.MustCompile(`\n+`)
	InstalledPackagesRegex    = regexp.MustCompile(`(?m)^Installed:\s*.*?\n`)
	UpdatedPackagesRegex      = regexp.MustCompile(`(?m)^Updated:\s*.*?\n`)
	DependencyUpdatedRegex    = regexp.MustCompile(`(?m)^Dependency Updated:\s*.*?\n`)
	CompleteMessageRegex      = regexp.MustCompile(`(?m)^Complete!\s*`)
	DownloadingPackagesRegex  = regexp.MustCompile(`(?m)^Downloading Packages:\n(?:.*\n)+^(\(\d+/\d+\): .*\n)+`)
	InstallingPackagesRegex   = regexp.MustCompile(`(?m)^(Installing|Upgrading|Removing|Erasing):.*\n(?:.*\n)*?^Complete!`)
)

// dockerRegexes list regular expressions of lines to keep in a docker build output
var dockerRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^#\d+ building with ".+" instance using docker driver$`),         // Matches the build instance line
	regexp.MustCompile(`(?m)^(#\d+) \[internal\] .+$`),                                       // Matches internal Docker steps
	regexp.MustCompile(`(?m)^(#\d+) \[\d+/\d+\] (FROM|WORKDIR|COPY|RUN|CMD|ENTRYPOINT) .+$`), // Matches Dockerfile instructions like FROM, WORKDIR, etc.
	regexp.MustCompile(`(?m)^(#\d+) DONE \d+\.\ds$`),                                         // Matches DONE lines with timings
	regexp.MustCompile(`(?m)^#\d+ exporting to image$`),
}

// yumRegexes gathers them into a slice
var yumRegexes = []*regexp.Regexp{
	DownloadingPackagesRegex,
	LastMetadataCheckRegex,
	InstallingPackagesRegex,
	PackageDetailsRegex,
	DependenciesResolvedRegex,
	RunningTransactionRegex,
	InstalledPackagesRegex,
	UpdatedPackagesRegex,
	DependencyUpdatedRegex,
	CompleteMessageRegex,
	TransactionSummaryRegex,
	VerifyingRegex,
}

// keyTypes define common opening/closing secret combinations
var keyTypes = []KeyType{
	{"-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"},
	{"-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"},
	{"-----BEGIN DSA PRIVATE KEY-----", "-----END DSA PRIVATE KEY-----"},
	{"-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"},
	{"-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"},
	{"-----BEGIN EC PARAMETERS-----", "-----END EC PARAMETERS-----"},
	{`"ssh-`, `"`},
	{"SHA256:", "\n"},
	{"glpat-", "\n"}, // For GitLab personal access tokens
	{"ghp_", "\""},   // For GitHub personal access tokens
	{"DefaultEndpointsProtocol=https;AccountName=", "\""},       // For Azure DevOps
	{"\"type\": \"service_account\"", "}"},                      // For GCP DevOps
	{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ""},                // For JWT Tokens
	{"vault_approle_secret_id=", "\""},                          // For Vault AppRole IDs
	{"apiVersion: v1", "contexts:"},                             // For Kubernetes Configs
	{"sk_live_", "\""},                                          // For Stripe Keys
	{"aws_access_key_id=", "aws_secret_access_key="},            // For AWS DevOps
	{`{"auths":{"https://index.docker.io/v1/":{"auth":`, "}}}"}, // For Docker Configs
	{`"arn:aws:`, `",`},

	// GPG Encrypted and Signed Messages
	{"-----BEGIN PGP MESSAGE-----", "-----END PGP MESSAGE-----"},
	{"-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----END PGP PUBLIC KEY BLOCK-----"},
	{"-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----"},
	{"-----BEGIN PGP SIGNATURE-----", "-----END PGP SIGNATURE-----"},
	{"-----BEGIN PGP SIGNED MESSAGE-----", "-----END PGP SIGNED MESSAGE-----"},

	// Other Encrypted/Signed Messages
	{"-----BEGIN ENCRYPTED MESSAGE-----", "-----END ENCRYPTED MESSAGE-----"},
	{"-----BEGIN SIGNATURE-----", "-----END SIGNATURE-----"},
}

// Scrub removes secrets from an input string using a header/footer substring approach
func Scrub(input string) (output string) {
	input = Rinse(input)
	for _, keyType := range keyTypes {
		start := strings.Index(input, keyType.Opening)
		end := strings.Index(input, keyType.Closing)
		if start != -1 {
			if keyType.Closing == "" {
				// If there's no specific closing string, assume it's the end of the line
				end = strings.Index(input[start:], "\n")
				if end == -1 {
					end = len(input) // Assume it goes till the end of the string
				} else {
					end += start // Adjust for the start position
				}
			} else if end != -1 {
				end += len(keyType.Closing)
			}
			if end > start {
				input = input[:start] + "[CLEANED]" + input[end:]
			}
		}
	}
	output = strings.Clone(input)
	input = ""
	return
}

// Rinse runs the TruncateDockerBuild and TruncateYumUpdate on the input string
func Rinse(input string) (output string) {
	output = strings.Clone(input)
	output = RemoveAnsiEscapeCodes(output)
	return
}

// RegexRemoveAnsiEscapeCodes matches all ANSI escape does
var RegexRemoveAnsiEscapeCodes = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// RemoveAnsiEscapeCodes removes ANSI escape codes from a string
func RemoveAnsiEscapeCodes(input string) string {
	return RegexRemoveAnsiEscapeCodes.ReplaceAllString(input, "")
}

type secretPatternLength int
type secretPattern []string

type secretPatterns map[secretPatternLength]secretPattern

func (sp secretPatterns) Validate() error {
	if sp == nil || len(sp) == 0 {
		return fmt.Errorf("secretPatterns map is empty or nil")
	}
	for key, value := range sp {
		if key == 0 {
			return fmt.Errorf("invalid key: empty string")
		}
		if len(value) == 0 {
			return fmt.Errorf("invalid value for key %d: empty string", key)
		}
	}
	return nil
}

const (
	MaxSecretPatternLength int = 1024
	MinSecretPatternLength int = 3
	MinSecretLength        int = 3
	MaxSecretLength        int = 1024
)
