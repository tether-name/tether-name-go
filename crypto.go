package tether

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// loadPrivateKey loads an RSA private key from the given options
func loadPrivateKey(opts Options) (*rsa.PrivateKey, error) {
	// Try PEM bytes first
	if len(opts.PrivateKeyPEM) > 0 {
		return parsePrivateKeyPEM(opts.PrivateKeyPEM)
	}
	
	// Try DER bytes next
	if len(opts.PrivateKeyDER) > 0 {
		return parsePrivateKeyDER(opts.PrivateKeyDER)
	}
	
	// Try file path
	if opts.PrivateKeyPath != "" {
		return loadPrivateKeyFromFile(opts.PrivateKeyPath)
	}
	
	return nil, &KeyLoadError{
		Message: "no private key provided",
		Err:     ErrKeyLoad,
	}
}

// loadPrivateKeyFromFile loads a private key from a file path
func loadPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &KeyLoadError{
			Message: fmt.Sprintf("failed to read key file: %s", path),
			Err:     err,
		}
	}
	
	// Try PEM format first
	if block, _ := pem.Decode(data); block != nil {
		return parsePrivateKeyDER(block.Bytes)
	}
	
	// Try raw DER format
	return parsePrivateKeyDER(data)
}

// parsePrivateKeyPEM parses a PEM-encoded private key
func parsePrivateKeyPEM(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, &KeyLoadError{
			Message: "failed to decode PEM block",
			Err:     ErrKeyLoad,
		}
	}
	
	return parsePrivateKeyDER(block.Bytes)
}

// parsePrivateKeyDER parses a DER-encoded private key
func parsePrivateKeyDER(derData []byte) (*rsa.PrivateKey, error) {
	// Try PKCS#1 format first
	if key, err := x509.ParsePKCS1PrivateKey(derData); err == nil {
		return key, nil
	}
	
	// Try PKCS#8 format
	keyInterface, err := x509.ParsePKCS8PrivateKey(derData)
	if err != nil {
		return nil, &KeyLoadError{
			Message: "failed to parse private key",
			Err:     err,
		}
	}
	
	rsaKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, &KeyLoadError{
			Message: "key is not an RSA private key",
			Err:     ErrKeyLoad,
		}
	}
	
	return rsaKey, nil
}

// signChallenge signs a challenge string using RSA SHA256 and returns URL-safe base64 (no padding)
func signChallenge(privateKey *rsa.PrivateKey, challenge string) (string, error) {
	// Hash the challenge with SHA256
	hashed := sha256.Sum256([]byte(challenge))
	
	// Sign the hash using RSA PKCS#1 v1.5 with SHA256
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign challenge: %w", err)
	}
	
	// Encode as URL-safe base64 without padding
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(signature)
	
	return encoded, nil
}

// verifySignature verifies a signature against a challenge using the public key (for testing)
func verifySignature(publicKey *rsa.PublicKey, challenge, signature string) error {
	// Decode the URL-safe base64 signature (no padding)
	sigBytes, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	
	// Hash the challenge with SHA256
	hashed := sha256.Sum256([]byte(challenge))
	
	// Verify the signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], sigBytes)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	
	return nil
}

// generateTestKeyPair generates an RSA key pair for testing (2048-bit)
func generateTestKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// privateKeyToPEM converts an RSA private key to PEM format
func privateKeyToPEM(key *rsa.PrivateKey) []byte {
	derKey := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derKey,
	}
	return pem.EncodeToMemory(block)
}

// privateKeyToDER converts an RSA private key to DER format
func privateKeyToDER(key *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(key)
}

// normalizeChallenge ensures the challenge is properly formatted
func normalizeChallenge(challenge string) string {
	return strings.TrimSpace(challenge)
}