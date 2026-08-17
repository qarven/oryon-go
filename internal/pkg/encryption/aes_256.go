package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

var (
	// ErrPlaintextEmpty indicates an empty plaintext input.
	ErrPlaintextEmpty = errors.New("encryption: plaintext is empty")
	// ErrInvalidKeyLength indicates the key length is invalid.
	ErrInvalidKeyLength = errors.New("encryption: invalid key length")
	// ErrUnexpectedNonceSize indicates a nonce size mismatch.
	ErrUnexpectedNonceSize = errors.New("encryption: unexpected nonce size")
	// ErrCiphertextTooShort indicates a truncated ciphertext.
	ErrCiphertextTooShort = errors.New("encryption: ciphertext too short")
	// ErrUnsupportedCiphertextVersion indicates an unsupported ciphertext version.
	ErrUnsupportedCiphertextVersion = errors.New("encryption: unsupported ciphertext version")
	// ErrDecryptFailed indicates decryption failure.
	ErrDecryptFailed = errors.New("encryption: decrypt failed")
)

// Ciphertext format (binary):
// [0..1]   uint16 version (currently 1)
// [2..13]  12-byte nonce
// [14..]   gcm.Seal output (ciphertext + tag)
const aesGCMVersion uint16 = 1

const (
	gcmNonceSize = 12
	aesKeyLen    = 32
)

// AES256Encryptor implements Encryptor using AES-256.
type AES256Encryptor struct {
	key []byte
}

// NewAES256Encryptor constructs an AES-256 encryptor.
func NewAES256Encryptor(key []byte) (*AES256Encryptor, error) {
	if len(key) != aesKeyLen {
		return nil, ErrInvalidKeyLength
	}

	return &AES256Encryptor{key: key}, nil
}

// Encrypt encrypts plaintext with AES-256-GCM.
func (e *AES256Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, ErrPlaintextEmpty
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if gcm.NonceSize() != gcmNonceSize {
		return nil, ErrUnexpectedNonceSize
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends ciphertext+tag to the first arg; we pass nil to allocate a fresh slice.
	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 2+gcmNonceSize+len(sealed))
	binary.BigEndian.PutUint16(out[0:2], aesGCMVersion)
	copy(out[2:2+gcmNonceSize], nonce)
	copy(out[2+gcmNonceSize:], sealed)

	return out, nil
}

// Decrypt decrypts ciphertext with AES-256-GCM.
func (e *AES256Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 2+gcmNonceSize+1 {
		return nil, ErrCiphertextTooShort
	}

	version := binary.BigEndian.Uint16(ciphertext[0:2])
	if version != aesGCMVersion {
		return nil, ErrUnsupportedCiphertextVersion
	}

	nonce := ciphertext[2 : 2+gcmNonceSize]
	sealed := ciphertext[2+gcmNonceSize:]

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if gcm.NonceSize() != gcmNonceSize {
		return nil, ErrUnexpectedNonceSize
	}

	plain, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		// Important: do not leak whether it was "wrong scope" vs "wrong key" vs "tampered".
		return nil, ErrDecryptFailed
	}

	return plain, nil
}
