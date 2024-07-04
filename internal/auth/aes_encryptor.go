package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
)

// NonceLength the length of the nonce to use
var NonceLength = 12

// AESEncryptor represent an encryptor leveraging AES-GCM.
// GCM mode operation is used to ensure the encryption is authenticated.
type AESEncryptor struct {
	Key []byte

	mutex sync.Mutex
}

// NewAESEncryptor create an instance of the AESEncryptor
func NewAESEncryptor(secret string) *AESEncryptor {
	// SHA256 derives the secret into a 32 bytes key compatible with AES
	h := sha256.New()
	h.Write([]byte(secret))
	return &AESEncryptor{
		Key: h.Sum(nil),
	}
}

// Encrypt a payload
func (ae *AESEncryptor) Encrypt(message string) (string, error) {
	ae.mutex.Lock()
	defer ae.mutex.Unlock()

	plaintext := []byte(message)

	block, err := aes.NewCipher(ae.Key)
	if err != nil {
		return "", fmt.Errorf("unable to create cipher: %v", err)
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, NonceLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("unable to generate nonce: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("unable to create GCM block cipher")
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	ciphertextAndNonce := append(ciphertext, nonce...)
	encmess := base64.StdEncoding.EncodeToString(ciphertextAndNonce)
	return encmess, nil
}

// Decrypt a payload
func (ae *AESEncryptor) Decrypt(securemess string) (string, error) {
	ae.mutex.Lock()
	defer ae.mutex.Unlock()

	ciphertextAndNonce, err := base64.StdEncoding.DecodeString(securemess)
	if err != nil {
		return "", fmt.Errorf("unable to b64 decode secure message: %w", err)
	}

	block, err := aes.NewCipher(ae.Key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	cutIdx := len(ciphertextAndNonce) - NonceLength
	nonce := ciphertextAndNonce[cutIdx:]
	ciphertext := ciphertextAndNonce[:cutIdx]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return string(plaintext), nil
}
