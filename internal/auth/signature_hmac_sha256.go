package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// HmacSha256Computer represent a producer and verifier of HMAC SHA256 signatures
// SHA256 is prefered over SHA1 for the security margin it implies but both would be ok at this time
// even if SHA1 is known to be vulnerable to collision attacks.
type HmacSha256Computer struct {
	secret string

	mutex sync.Mutex
}

// NewHmacSha256Computer create an instance of HMAC SHA256 computer
func NewHmacSha256Computer(secret string) *HmacSha256Computer {
	return &HmacSha256Computer{secret: secret}
}

// ProduceSignature produce a signature for the given data
func (hsc *HmacSha256Computer) ProduceSignature(data []byte) string {
	hsc.mutex.Lock()
	defer hsc.mutex.Unlock()

	h := hmac.New(sha256.New, []byte(hsc.secret))

	// sign the original URL to make sure we don't allow open redirect where one can simply craft any URL
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
