package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldEncrypt(t *testing.T) {
	e := NewAESEncryptor("mysecretkey")

	ct, err := e.Encrypt("This is a payload to be encrypted")
	assert.NoError(t, err)

	assert.NotEmpty(t, ct)

	decrypted, err := e.Decrypt(ct)
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
