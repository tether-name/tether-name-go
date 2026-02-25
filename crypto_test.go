package tether

import (
	"strings"
	"testing"
)

func TestGenerateTestKeyPair(t *testing.T) {
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	if key.Size() != 256 { // 2048 bits = 256 bytes
		t.Errorf("Expected key size 256 bytes, got %d", key.Size())
	}
}

func TestPrivateKeyToPEM(t *testing.T) {
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	pemData := privateKeyToPEM(key)
	if len(pemData) == 0 {
		t.Error("PEM data is empty")
	}
	
	if !strings.Contains(string(pemData), "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("PEM data does not contain expected header")
	}
	
	if !strings.Contains(string(pemData), "-----END RSA PRIVATE KEY-----") {
		t.Error("PEM data does not contain expected footer")
	}
}

func TestPrivateKeyToDER(t *testing.T) {
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	derData := privateKeyToDER(key)
	if len(derData) == 0 {
		t.Error("DER data is empty")
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	// Generate a test key and convert to PEM
	originalKey, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	pemData := privateKeyToPEM(originalKey)
	
	// Parse the PEM data back to a key
	parsedKey, err := parsePrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("Failed to parse PEM data: %v", err)
	}
	
	// Compare the keys
	if parsedKey.Size() != originalKey.Size() {
		t.Errorf("Key sizes don't match: original=%d, parsed=%d", originalKey.Size(), parsedKey.Size())
	}
	
	if !parsedKey.Equal(originalKey) {
		t.Error("Parsed key does not match original")
	}
}

func TestParsePrivateKeyDER(t *testing.T) {
	// Generate a test key and convert to DER
	originalKey, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	derData := privateKeyToDER(originalKey)
	
	// Parse the DER data back to a key
	parsedKey, err := parsePrivateKeyDER(derData)
	if err != nil {
		t.Fatalf("Failed to parse DER data: %v", err)
	}
	
	// Compare the keys
	if parsedKey.Size() != originalKey.Size() {
		t.Errorf("Key sizes don't match: original=%d, parsed=%d", originalKey.Size(), parsedKey.Size())
	}
	
	if !parsedKey.Equal(originalKey) {
		t.Error("Parsed key does not match original")
	}
}

func TestSignChallenge(t *testing.T) {
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	challenge := "test-challenge-123"
	signature, err := signChallenge(key, challenge)
	if err != nil {
		t.Fatalf("Failed to sign challenge: %v", err)
	}
	
	if signature == "" {
		t.Error("Signature is empty")
	}
	
	// Signature should be URL-safe base64 without padding
	if strings.Contains(signature, "+") || strings.Contains(signature, "/") || strings.Contains(signature, "=") {
		t.Error("Signature is not URL-safe base64 without padding")
	}
}

func TestVerifySignature(t *testing.T) {
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	challenge := "test-challenge-123"
	signature, err := signChallenge(key, challenge)
	if err != nil {
		t.Fatalf("Failed to sign challenge: %v", err)
	}
	
	// Verify the signature
	err = verifySignature(&key.PublicKey, challenge, signature)
	if err != nil {
		t.Errorf("Failed to verify signature: %v", err)
	}
	
	// Verify that a different challenge fails
	err = verifySignature(&key.PublicKey, "different-challenge", signature)
	if err == nil {
		t.Error("Verification should fail for different challenge")
	}
	
	// Verify that a different signature fails
	wrongSignature := "invalid-signature"
	err = verifySignature(&key.PublicKey, challenge, wrongSignature)
	if err == nil {
		t.Error("Verification should fail for invalid signature")
	}
}

func TestNormalizeChallenge(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test", "test"},
		{" test ", "test"},
		{"\t test \n", "test"},
		{"", ""},
		{"  ", ""},
	}
	
	for _, test := range tests {
		result := normalizeChallenge(test.input)
		if result != test.expected {
			t.Errorf("normalizeChallenge(%q) = %q, expected %q", test.input, result, test.expected)
		}
	}
}

func TestLoadPrivateKeyOptions(t *testing.T) {
	// Generate a test key
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	pemData := privateKeyToPEM(key)
	derData := privateKeyToDER(key)
	
	// Test with PEM bytes
	opts := Options{
		PrivateKeyPEM: pemData,
	}
	loadedKey, err := loadPrivateKey(opts)
	if err != nil {
		t.Errorf("Failed to load key from PEM bytes: %v", err)
	}
	if !loadedKey.Equal(key) {
		t.Error("Loaded key from PEM bytes does not match original")
	}
	
	// Test with DER bytes
	opts = Options{
		PrivateKeyDER: derData,
	}
	loadedKey, err = loadPrivateKey(opts)
	if err != nil {
		t.Errorf("Failed to load key from DER bytes: %v", err)
	}
	if !loadedKey.Equal(key) {
		t.Error("Loaded key from DER bytes does not match original")
	}
	
	// Test with no key data (should fail)
	opts = Options{}
	_, err = loadPrivateKey(opts)
	if err == nil {
		t.Error("Expected error when no key data provided")
	}
}

func TestSignChallengeConsistency(t *testing.T) {
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	challenge := "consistent-challenge-test"
	
	// Sign the same challenge multiple times
	sig1, err := signChallenge(key, challenge)
	if err != nil {
		t.Fatalf("Failed to sign challenge (1): %v", err)
	}
	
	sig2, err := signChallenge(key, challenge)
	if err != nil {
		t.Fatalf("Failed to sign challenge (2): %v", err)
	}
	
	// Signatures should be the same for PKCS#1 v1.5 (deterministic padding)
	if sig1 != sig2 {
		t.Error("Expected same signatures for same challenge with PKCS#1 v1.5")
	}
	
	// Both should verify correctly
	err = verifySignature(&key.PublicKey, challenge, sig1)
	if err != nil {
		t.Errorf("Failed to verify first signature: %v", err)
	}
	
	err = verifySignature(&key.PublicKey, challenge, sig2)
	if err != nil {
		t.Errorf("Failed to verify second signature: %v", err)
	}
}

func BenchmarkSignChallenge(b *testing.B) {
	key, err := generateTestKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	challenge := "benchmark-challenge"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signChallenge(key, challenge)
		if err != nil {
			b.Fatalf("Failed to sign challenge: %v", err)
		}
	}
}

func BenchmarkVerifySignature(b *testing.B) {
	key, err := generateTestKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	challenge := "benchmark-challenge"
	signature, err := signChallenge(key, challenge)
	if err != nil {
		b.Fatalf("Failed to sign challenge: %v", err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := verifySignature(&key.PublicKey, challenge, signature)
		if err != nil {
			b.Fatalf("Failed to verify signature: %v", err)
		}
	}
}