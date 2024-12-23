package verbose

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
)

type SecretBytes []byte

func (sb SecretBytes) Sha512() (string, error) {
	var err error
	defer func(e *error) {
		var ok bool
		r := recover()
		if r != nil {
			err, ok = r.(error)
			if !ok {
				log.Fatalf("caught recover() in verbose.SecretBytes.Sha512 when attempting "+
					"to bind recover() to error type: r = %v", r)
			}
		}
	}(&err)
	if len(sb) == 0 {
		return "", nil
	}
	if len(sb) < SecretMinLength {
		return "", fmt.Errorf("%s", "verbose.SecretMinLength %d requires len(SecretBytes) to be at "+
			"least %d bytes to be eligible for secrets protection. Adjust this value to include "+
			"shorter secrets. The lower the value, the longer verbose.Printf and verbose.Println "+
			"will take to safely remove all secrets")
	}
	hash := sha512.New()
	bytesWritten, writeErr := hash.Write(sb)
	if writeErr != nil {
		return "", fmt.Errorf("verbose.AddSecret triggered an error at hash.Write(secret) with: %v", writeErr)
	}
	if bytesWritten == 0 {
		return "", nil
	}
	checksum := hash.Sum(nil)
	return hex.EncodeToString(checksum), nil
}
