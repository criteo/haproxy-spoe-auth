package auth

// SignatureVerifier verify a signature
type SignatureVerifier interface {
	VerifySignature(signature []byte) bool
}

// SignatureProducer produces a signature
type SignatureProducer interface {
	ProduceSignature(data []byte) []byte
}
