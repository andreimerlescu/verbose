package verbose

import "testing"

func TestImportSecrets(t *testing.T) {
	hash1 := "95d9109bfbd8c260006acc5243ad1b28884cdd1198e13932e7b30d08878355e125329df10752d7ff861f4baccb8b75f7572447ca808fe97f6ca33a5276452a06"
	hash2 := "158eddbc659fde13fea6e818262bc315f9526449b3cc57a6fc2d6b8aa6b4fe1eac82a6e5574c0479846a102a9f9745c65998973112382c3f9e4cce384036f210"
	hash1Len := 9
	hash2Len := 10
	_, err := ImportSecrets(map[string]int{
		hash1: hash1Len,
		hash2: hash2Len,
	})
	if err != nil {
		t.Errorf("ImportSecrets failed: %s", err)
	}
	if e := IsSecret(hash1); !e {
		t.Errorf("ImportSecrets failed. hash1 should be a secret. got %v", e)
	}
	if e := IsSecret(hash2); !e {
		t.Errorf("ImportSecrets failed. hash2 should be a secret. got %v", e)
	}
	err = RemoveSecret(SecretBytes(hash1))
	if err != nil {
		t.Errorf("RemoveSecret failed: %s", err)
	}
	err = RemoveSecret(SecretBytes(hash2))
	if err != nil {
		t.Errorf("RemoveSecret failed: %s", err)
	}
}

func TestSecretBytes_Sha512(t *testing.T) {
	tests := []struct {
		name    string
		sb      SecretBytes
		want    string
		wantErr bool
	}{
		{
			name:    "test success",
			sb:      SecretBytes("secret1"),
			want:    "1c3e9787e63aa086675efe17a9b2b1adbeaddd19283d8bfe364a8e044f0cc24b2cb804d1136685069f0d9bd929fd79f96b89762a2f10917e6a21495b5d080ee1",
			wantErr: false,
		},
		{
			name:    "test error",
			sb:      SecretBytes(`a`),
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.sb.Sha512()
			if (err != nil) != tt.wantErr {
				t.Errorf("Sha512() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Sha512() got = %v, want %v", got, tt.want)
			}
		})
	}
}
