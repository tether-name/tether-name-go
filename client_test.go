package tether

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	// Generate a test key
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	pemData := privateKeyToPEM(key)
	
	tests := []struct {
		name        string
		opts        Options
		expectError bool
	}{
		{
			name: "with credential ID and PEM bytes",
			opts: Options{
				CredentialID:  "test-credential",
				PrivateKeyPEM: pemData,
			},
			expectError: false,
		},
		{
			name: "with credential ID and DER bytes",
			opts: Options{
				CredentialID:  "test-credential",
				PrivateKeyDER: privateKeyToDER(key),
			},
			expectError: false,
		},
		{
			name: "missing credential ID",
			opts: Options{
				PrivateKeyPEM: pemData,
			},
			expectError: true,
		},
		{
			name: "missing private key",
			opts: Options{
				CredentialID: "test-credential",
			},
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.opts)
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			
			if client.credentialID != tt.opts.CredentialID {
				t.Errorf("Expected credential ID %q, got %q", tt.opts.CredentialID, client.credentialID)
			}
			
			if client.baseURL != DefaultBaseURL {
				t.Errorf("Expected base URL %q, got %q", DefaultBaseURL, client.baseURL)
			}
		})
	}
}

func TestNewClientWithEnvironmentVariables(t *testing.T) {
	// Generate a test key and create a temporary file
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	pemData := privateKeyToPEM(key)
	
	// Create a temporary file for the private key
	tmpFile, err := os.CreateTemp("", "test-key-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	
	if _, err := tmpFile.Write(pemData); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()
	
	// Set environment variables
	os.Setenv("TETHER_CREDENTIAL_ID", "env-credential")
	os.Setenv("TETHER_PRIVATE_KEY_PATH", tmpFile.Name())
	defer func() {
		os.Unsetenv("TETHER_CREDENTIAL_ID")
		os.Unsetenv("TETHER_PRIVATE_KEY_PATH")
	}()
	
	// Create client with empty options (should use env vars)
	client, err := NewClient(Options{})
	if err != nil {
		t.Fatalf("Failed to create client with env vars: %v", err)
	}
	
	if client.credentialID != "env-credential" {
		t.Errorf("Expected credential ID from env var, got %q", client.credentialID)
	}
}

func TestClientSign(t *testing.T) {
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	client := &TetherClient{
		credentialID: "test-credential",
		privateKey:   key,
	}
	
	challenge := "test-challenge"
	proof, err := client.Sign(challenge)
	if err != nil {
		t.Fatalf("Failed to sign challenge: %v", err)
	}
	
	if proof == "" {
		t.Error("Proof is empty")
	}
	
	// Verify the proof locally
	err = verifySignature(&key.PublicKey, challenge, proof)
	if err != nil {
		t.Errorf("Failed to verify proof locally: %v", err)
	}
}

func TestClientRequestChallenge(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		
		if r.URL.Path != "/challenge" {
			t.Errorf("Expected /challenge path, got %s", r.URL.Path)
		}
		
		expectedUserAgent := UserAgent
		if r.Header.Get("User-Agent") != expectedUserAgent {
			t.Errorf("Expected User-Agent %q, got %q", expectedUserAgent, r.Header.Get("User-Agent"))
		}
		
		response := challengeResponse{Code: "test-challenge-uuid"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	client := &TetherClient{
		credentialID: "test-credential",
		privateKey:   key,
		baseURL:      server.URL,
		httpClient:   &http.Client{Timeout: 5 * time.Second},
	}
	
	ctx := context.Background()
	challenge, err := client.RequestChallenge(ctx)
	if err != nil {
		t.Fatalf("Failed to request challenge: %v", err)
	}
	
	if challenge != "test-challenge-uuid" {
		t.Errorf("Expected challenge %q, got %q", "test-challenge-uuid", challenge)
	}
}

func TestClientSubmitProof(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		
		if r.URL.Path != "/challenge/verify" {
			t.Errorf("Expected /challenge/verify path, got %s", r.URL.Path)
		}
		
		// Parse request body
		var req verifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
		}
		
		// Check request fields
		if req.Challenge != "test-challenge" {
			t.Errorf("Expected challenge %q, got %q", "test-challenge", req.Challenge)
		}
		
		if req.CredentialID != "test-credential" {
			t.Errorf("Expected credential ID %q, got %q", "test-credential", req.CredentialID)
		}
		
		if req.Proof == "" {
			t.Error("Proof is empty")
		}
		
		// Send success response
		t0 := time.Now().Add(-30 * 24 * time.Hour); registeredSince := &EpochTime{t0} // 30 days ago
		response := verifyResponse{
			Valid:           true,
			VerifyURL:       "https://tether.name/check?challenge=test-challenge",
			AgentName:       "Test Agent",
			Email:           "test@example.com",
			RegisteredSince: registeredSince,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	client := &TetherClient{
		credentialID: "test-credential",
		privateKey:   key,
		baseURL:      server.URL,
		httpClient:   &http.Client{Timeout: 5 * time.Second},
	}
	
	ctx := context.Background()
	challenge := "test-challenge"
	proof := "test-proof"
	
	result, err := client.SubmitProof(ctx, challenge, proof)
	if err != nil {
		t.Fatalf("Failed to submit proof: %v", err)
	}
	
	if !result.Verified {
		t.Error("Expected verification to succeed")
	}
	
	if result.AgentName != "Test Agent" {
		t.Errorf("Expected agent name %q, got %q", "Test Agent", result.AgentName)
	}
	
	if result.Email != "test@example.com" {
		t.Errorf("Expected email %q, got %q", "test@example.com", result.Email)
	}
	
	if result.Challenge != challenge {
		t.Errorf("Expected challenge %q, got %q", challenge, result.Challenge)
	}
}

func TestClientVerify(t *testing.T) {
	challengeRequested := false
	proofSubmitted := false
	
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		switch r.URL.Path {
		case "/challenge":
			challengeRequested = true
			response := challengeResponse{Code: "test-challenge-uuid"}
			json.NewEncoder(w).Encode(response)
			
		case "/challenge/verify":
			proofSubmitted = true
			t0 := time.Now().Add(-30 * 24 * time.Hour); registeredSince := &EpochTime{t0}
			response := verifyResponse{
				Valid:           true,
				VerifyURL:       "https://tether.name/check?challenge=test-challenge-uuid",
				AgentName:       "Test Agent",
				Email:           "test@example.com",
				RegisteredSince: registeredSince,
			}
			json.NewEncoder(w).Encode(response)
			
		default:
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	client := &TetherClient{
		credentialID: "test-credential",
		privateKey:   key,
		baseURL:      server.URL,
		httpClient:   &http.Client{Timeout: 5 * time.Second},
	}
	
	ctx := context.Background()
	result, err := client.Verify(ctx)
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}
	
	if !challengeRequested {
		t.Error("Challenge was not requested")
	}
	
	if !proofSubmitted {
		t.Error("Proof was not submitted")
	}
	
	if !result.Verified {
		t.Error("Expected verification to succeed")
	}
	
	if result.AgentName != "Test Agent" {
		t.Errorf("Expected agent name %q, got %q", "Test Agent", result.AgentName)
	}
}

func TestClientErrorHandling(t *testing.T) {
	// Test network errors
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	client := &TetherClient{
		credentialID: "test-credential",
		privateKey:   key,
		baseURL:      "http://invalid-url-that-does-not-exist.local",
		httpClient:   &http.Client{Timeout: 1 * time.Second},
	}
	
	ctx := context.Background()
	
	// Test RequestChallenge error
	_, err = client.RequestChallenge(ctx)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
	
	// Test SubmitProof error
	_, err = client.SubmitProof(ctx, "challenge", "proof")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
	
	// Test Verify error
	_, err = client.Verify(ctx)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestClientHTTPErrorCodes(t *testing.T) {
	// Test server returning error codes
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad Request"))
	}))
	defer server.Close()
	
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	client := &TetherClient{
		credentialID: "test-credential",
		privateKey:   key,
		baseURL:      server.URL,
		httpClient:   &http.Client{Timeout: 5 * time.Second},
	}
	
	ctx := context.Background()
	
	// Test RequestChallenge with error code
	_, err = client.RequestChallenge(ctx)
	if err == nil {
		t.Error("Expected error for HTTP 400")
	}
	
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Errorf("Expected APIError, got %T", err)
	} else if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, apiErr.StatusCode)
	}
}

func TestClientVerificationFailure(t *testing.T) {
	// Create a mock server that returns verification failure
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		switch r.URL.Path {
		case "/challenge":
			response := challengeResponse{Code: "test-challenge-uuid"}
			json.NewEncoder(w).Encode(response)
			
		case "/challenge/verify":
			response := verifyResponse{
				Valid: false,
				Error: "Invalid signature",
			}
			json.NewEncoder(w).Encode(response)
			
		default:
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	client := &TetherClient{
		credentialID: "test-credential",
		privateKey:   key,
		baseURL:      server.URL,
		httpClient:   &http.Client{Timeout: 5 * time.Second},
	}
	
	ctx := context.Background()
	result, err := client.Verify(ctx)
	
	// Should return error for failed verification
	if err == nil {
		t.Error("Expected error for failed verification")
	}
	
	verifyErr, ok := err.(*VerificationError)
	if !ok {
		t.Errorf("Expected VerificationError, got %T", err)
	}
	
	// Result should still be returned
	if result == nil {
		t.Fatal("Expected result even for failed verification")
	}
	
	if result.Verified {
		t.Error("Expected verification to fail")
	}
	
	if !strings.Contains(result.Error, "Invalid signature") {
		t.Errorf("Expected error message to contain 'Invalid signature', got %q", result.Error)
	}
	
	if !strings.Contains(verifyErr.Message, "Invalid signature") {
		t.Errorf("Expected error message to contain 'Invalid signature', got %q", verifyErr.Message)
	}
}

func TestClientContextCancellation(t *testing.T) {
	// Create a mock server with delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		response := challengeResponse{Code: "test-challenge-uuid"}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	
	client := &TetherClient{
		credentialID: "test-credential",
		privateKey:   key,
		baseURL:      server.URL,
		httpClient:   &http.Client{Timeout: 5 * time.Second},
	}
	
	// Create context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	
	_, err = client.RequestChallenge(ctx)
	if err == nil {
		t.Error("Expected error for cancelled context")
	}
	
	if !strings.Contains(err.Error(), "context") {
		t.Errorf("Expected context-related error, got: %v", err)
	}
}