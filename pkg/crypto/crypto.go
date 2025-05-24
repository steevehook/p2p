package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey

	XPrivateKey []byte
	XPublicKey  []byte
}

func (kp *KeyPair) ID() string {
	sum := sha256.Sum256(kp.PublicKey)
	return hex.EncodeToString(sum[:8])
}

func (kp *KeyPair) Base64XPublicKey() string {
	return base64.StdEncoding.EncodeToString(kp.XPublicKey)
}

// NewKeyPair creates a new Ed25519 key pair and derives the corresponding X25519 key pair.
func NewKeyPair() (*KeyPair, error) {
	publicKey, privateKey, err := NewEd25519KeyPair()
	if err != nil {
		return nil, err
	}

	xPublicKey, xPrivateKey, err := ConvertEd25519ToX25519(privateKey.Seed())
	if err != nil {
		return nil, err
	}

	keyPair := &KeyPair{
		PublicKey:   publicKey,
		PrivateKey:  privateKey,
		XPrivateKey: xPrivateKey,
		XPublicKey:  xPublicKey,
	}
	return keyPair, nil
}

// NewEd25519KeyPair generates a new Ed25519 key pair.
func NewEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, err
}

// ConvertEd25519ToX25519 derives the X25519 key pair as byte slices from an Ed25519 private key seed.
func ConvertEd25519ToX25519(seed []byte) ([]byte, []byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("invalid ed25519 seed size: expected %d, got %d", ed25519.SeedSize, len(seed))
	}

	// clamp private key bytes according to Curve25519 rules
	clampPrivateKey := func(key []byte) []byte {
		clamped := make([]byte, 32)
		copy(clamped, key)
		clamped[0] &= 248
		clamped[31] &= 127
		clamped[31] |= 64
		return clamped
	}

	// hash the seed to derive the X25519 private scalar
	h := sha512.Sum512(seed)
	xPrivateKey := clampPrivateKey(h[:32])

	// derive the corresponding X25519 public key
	xPublicKey, err := curve25519.X25519(xPrivateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("could not compute X25519 public key: %w", err)
	}

	return xPublicKey, xPrivateKey, nil
}

// Base64DecodePublicKey decodes a base64 public key string into a 32-byte X25519 public key (as []byte)
func Base64DecodePublicKey(key string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid public key length: %d", len(data))
	}
	return data, nil
}

type SharedSecret []byte

// ComputeX25519SharedSecret performs ECDH using a given X25519 private key and another (peer) X25519 public key.
// privateKey is typically your own X25519 locally stored 32-byte private key (clamped).
// peerPublicKey is typically the peer's X25519 32-byte public key exchanged over the network.
func ComputeX25519SharedSecret(privateKey []byte, peerPublicKey []byte) (SharedSecret, error) {
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("invalid private key length: %d", len(privateKey))
	}
	if len(peerPublicKey) != 32 {
		return nil, fmt.Errorf("invalid public key length: %d", len(peerPublicKey))
	}

	sharedSecret, err := curve25519.X25519(privateKey, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not compute shared secret: %w", err)
	}
	return sharedSecret, nil
}

type AESKey []byte

// DeriveAESKey derives a 32-byte AES key using HKDF from the shared secret
func DeriveAESKey(sharedSecret []byte, salt []byte, info []byte) (AESKey, error) {
	h := hkdf.New(sha256.New, sharedSecret, salt, info)

	// AES-256 requires 32-byte key
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	return key, nil
}

func AESEncrypt(plaintext []byte, aesKey []byte) (string, error) {
	if len(aesKey) != 32 {
		return "", fmt.Errorf("invalid aes key length: %d bytes (expected 32)", len(aesKey))
	}

	// Initialize AES cipher with the 256-bit key
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to create aes cipher: %w", err)
	}

	// Use Galois/Counter Mode (GCM) for authenticated encryption
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create gcm mode: %w", err)
	}

	// Generate a random nonce of appropriate size
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// TODO:  we can pass down nonce as additional data for authentication

	// Encrypt and authenticate the plaintext
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	// Prepend nonce to ciphertext for use in decryption
	message := append(nonce, ciphertext...)

	// Base64 encode for safe transmission/storage
	encoded := base64.StdEncoding.EncodeToString(message)

	return encoded, nil
}

func AESDecrypt(encoded string, aesKey []byte) ([]byte, error) {
	if len(aesKey) != 32 {
		return nil, fmt.Errorf("invalid aes key length: %d bytes (expected 32)", len(aesKey))
	}

	// Decode the base64 encoded message back to raw bytes
	message, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode: %w", err)
	}

	// Create AES cipher with the 256-bit key
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	// Create GCM instance from the block cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcm mode: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(message) < nonceSize {
		return nil, fmt.Errorf("malformed ciphertext: message too short")
	}

	// Split nonce and ciphertext
	nonce, ciphertext := message[:nonceSize], message[nonceSize:]

	// TODO:  we can pass down nonce as additional data for authentication

	// Decrypt and authenticate ciphertext
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption/authentication failed: %w", err)
	}

	return plaintext, nil
}

func ChaChaEncrypt(plaintext []byte, key []byte) (string, error) {
	if len(key) != chacha20poly1305.KeySize {
		return "", fmt.Errorf("invalid key length: %d bytes (expected %d)", len(key), chacha20poly1305.KeySize)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", fmt.Errorf("failed to create chacha20-poly1305: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	message := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(message), nil
}

func ChaChaDecrypt(encoded string, key []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key length: %d bytes (expected %d)", len(key), chacha20poly1305.KeySize)
	}

	message, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode: %w", err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create chacha20-poly1305: %w", err)
	}

	nonceSize := chacha20poly1305.NonceSize
	if len(message) < nonceSize {
		return nil, fmt.Errorf("malformed ciphertext: message too short")
	}

	nonce, ciphertext := message[:nonceSize], message[nonceSize:]
	return aead.Open(nil, nonce, ciphertext, nil)
}
