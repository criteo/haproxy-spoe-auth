package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	DummySecret  = "dummy_secret"
	DummySecret2 = "another_secret"
)

func TestShouldProduceSignature(t *testing.T) {
	c := NewHmacSha256Computer(DummySecret)
	sig := c.ProduceSignature("http://my-littly-url.crto.in")
	assert.Equal(t, "33ba08400f391aaaffe1f54f3f2772473b6faa8f4b1b9bab3c71db8c572d4341", sig)
}

func TestShouldProduceSignatureOfEmptyString(t *testing.T) {
	c := NewHmacSha256Computer(DummySecret)
	sig := c.ProduceSignature("")
	assert.Equal(t, "ff61b6bcbd15af6ab2e369a1e92f30c611aae9b859425db70a7e01a0716b510a", sig)
}

func TestShouldVerifySignature(t *testing.T) {
	c := NewHmacSha256Computer(DummySecret)
	ok := c.VerifySignature("http://my-littly-url.crto.in", "33ba08400f391aaaffe1f54f3f2772473b6faa8f4b1b9bab3c71db8c572d4341")
	assert.True(t, ok)
}

func TestShouldVerifyBadSignature(t *testing.T) {
	c := NewHmacSha256Computer(DummySecret)
	ok := c.VerifySignature("http://my-littly-url.crto.in", "33ba08400")
	assert.False(t, ok)
}

func TestShouldProduceSignatureWithDifferentKeysAndHaveDifferentSignatures(t *testing.T) {
	sig1 := NewHmacSha256Computer(DummySecret).ProduceSignature("http://my-littly-url.crto.in")
	sig2 := NewHmacSha256Computer(DummySecret2).ProduceSignature("http://my-littly-url.crto.in")
	assert.True(t, sig1 != sig2, "signatures are equal %s", sig1)
}
