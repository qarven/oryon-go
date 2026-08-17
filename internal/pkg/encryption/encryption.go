package encryption

// Encryption defines the interface for encrypting/decrypting.
type Encryption interface {
	// Encrypt returns ciphertext for the given plaintext.
	Encrypt(plaintext []byte) ([]byte, error)
	// Decrypt returns plaintext for the given ciphertext.
	Decrypt(ciphertext []byte) ([]byte, error)
}
