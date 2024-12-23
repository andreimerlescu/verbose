package verbose

import (
	"slices"
	"strings"
	"testing"
)

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
