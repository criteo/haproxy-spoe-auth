package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldEncrypt(t *testing.T) {
	e := NewAESEncryptor("mysecretkey")

	ct, err := e.Encrypt("This is a payload to be encrypted")
	assert.NoError(t, err)

	assert.Equal(t, "IpfBlsuyW66PWV0D75xOnnKyFtHs1//EywFLU0ekpFKx1mMqvRB4BJw37PaYVgeFkXKKFFmHMNRKwPs15A==", ct)
}

func TestShouldDecrypt(t *testing.T) {
	e := NewAESEncryptor("mysecretkey")

	decrypted, err := e.Decrypt("IpfBlsuyW66PWV0D75xOnnKyFtHs1//EywFLU0ekpFKx1mMqvRB4BJw37PaYVgeFkXKKFFmHMNRKwPs15A==")
	assert.NoError(t, err)
	assert.Equal(t, "This is a payload to be encrypted", decrypted)
}

func TestShouldEncryptScramble(t *testing.T) {
	e := NewAESEncryptor("mysecretkey")

	ct1, err := e.Encrypt("This is a payload to be encrypted")
	assert.NoError(t, err)
	ct2, err := e.Encrypt("This is another payload to be encrypted")
	assert.NoError(t, err)

	assert.True(t, ct1 != ct2)
}
