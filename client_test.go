package tether

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
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
	var challengeRequested atomic.Bool
	var proofSubmitted atomic.Bool

	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/challenge":
			challengeRequested.Store(true)
			response := challengeResponse{Code: "test-challenge-uuid"}
			json.NewEncoder(w).Encode(response)

		case "/challenge/verify":
			proofSubmitted.Store(true)
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
	
	if !challengeRequested.Load() {
		t.Error("Challenge was not requested")
	}

	if !proofSubmitted.Load() {
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

func TestNewClientWithApiKeyOnly(t *testing.T) {
	// Should succeed with only an API key (no credential ID or private key)
	client, err := NewClient(Options{
		ApiKey: "test-api-key",
	})
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if client.apiKey != "test-api-key" {
		t.Errorf("Expected apiKey %q, got %q", "test-api-key", client.apiKey)
	}

	if client.credentialID != "" {
		t.Errorf("Expected empty credentialID, got %q", client.credentialID)
	}

	if client.privateKey != nil {
		t.Error("Expected nil privateKey")
	}
}

func TestNewClientWithApiKeyAndCredential(t *testing.T) {
	key, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	client, err := NewClient(Options{
		ApiKey:        "test-api-key",
		CredentialID:  "test-credential",
		PrivateKeyPEM: privateKeyToPEM(key),
	})
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if client.apiKey != "test-api-key" {
		t.Errorf("Expected apiKey %q, got %q", "test-api-key", client.apiKey)
	}

	if client.credentialID != "test-credential" {
		t.Errorf("Expected credentialID %q, got %q", "test-credential", client.credentialID)
	}

	if client.privateKey == nil {
		t.Error("Expected privateKey to be loaded")
	}
}

func TestNewClientWithApiKeyEnvVar(t *testing.T) {
	os.Setenv("TETHER_API_KEY", "env-api-key")
	defer os.Unsetenv("TETHER_API_KEY")

	client, err := NewClient(Options{})
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if client.apiKey != "env-api-key" {
		t.Errorf("Expected apiKey %q, got %q", "env-api-key", client.apiKey)
	}
}

func TestSignRequiresPrivateKey(t *testing.T) {
	client := &TetherClient{
		apiKey: "test-api-key",
	}

	_, err := client.Sign("test-challenge")
	if err == nil {
		t.Error("Expected error when signing without private key")
	}

	if !strings.Contains(err.Error(), "private key is required") {
		t.Errorf("Expected 'private key is required' error, got: %v", err)
	}
}

func TestSubmitProofRequiresCredentialID(t *testing.T) {
	client := &TetherClient{
		apiKey:     "test-api-key",
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	ctx := context.Background()
	_, err := client.SubmitProof(ctx, "challenge", "proof")
	if err == nil {
		t.Error("Expected error when submitting proof without credential ID")
	}

	if !strings.Contains(err.Error(), "credential ID is required") {
		t.Errorf("Expected 'credential ID is required' error, got: %v", err)
	}
}

func TestCreateAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		if r.URL.Path != "/credentials/issue" {
			t.Errorf("Expected /credentials/issue path, got %s", r.URL.Path)
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-api-key" {
			t.Errorf("Expected Authorization header %q, got %q", "Bearer test-api-key", authHeader)
		}

		var req issueCredentialRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
		}

		if req.AgentName != "my-agent" {
			t.Errorf("Expected agentName %q, got %q", "my-agent", req.AgentName)
		}

		if req.Description != "Test agent" {
			t.Errorf("Expected description %q, got %q", "Test agent", req.Description)
		}

		response := issueCredentialResponse{
			ID:                "cred-123",
			AgentName:         "my-agent",
			Description:       "Test agent",
			CreatedAt:         1700000000000,
			RegistrationToken: "reg-token-abc",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &TetherClient{
		apiKey:     "test-api-key",
		baseURL:    server.URL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	ctx := context.Background()
	agent, err := client.CreateAgent(ctx, "my-agent", "Test agent")
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}

	if agent.ID != "cred-123" {
		t.Errorf("Expected ID %q, got %q", "cred-123", agent.ID)
	}

	if agent.AgentName != "my-agent" {
		t.Errorf("Expected AgentName %q, got %q", "my-agent", agent.AgentName)
	}

	if agent.RegistrationToken != "reg-token-abc" {
		t.Errorf("Expected RegistrationToken %q, got %q", "reg-token-abc", agent.RegistrationToken)
	}

	if agent.CreatedAt != 1700000000000 {
		t.Errorf("Expected CreatedAt %d, got %d", 1700000000000, agent.CreatedAt)
	}
}

func TestListAgents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}

		if r.URL.Path != "/credentials" {
			t.Errorf("Expected /credentials path, got %s", r.URL.Path)
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-api-key" {
			t.Errorf("Expected Authorization header %q, got %q", "Bearer test-api-key", authHeader)
		}

		// API returns "issuedAt" instead of "createdAt"
		response := `[
			{"id":"cred-1","agentName":"agent-1","description":"First","issuedAt":1700000000000,"lastVerifiedAt":1700001000000},
			{"id":"cred-2","agentName":"agent-2","description":"Second","issuedAt":1700002000000}
		]`
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(response))
	}))
	defer server.Close()

	client := &TetherClient{
		apiKey:     "test-api-key",
		baseURL:    server.URL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	ctx := context.Background()
	agents, err := client.ListAgents(ctx)
	if err != nil {
		t.Fatalf("Failed to list agents: %v", err)
	}

	if len(agents) != 2 {
		t.Fatalf("Expected 2 agents, got %d", len(agents))
	}

	if agents[0].ID != "cred-1" {
		t.Errorf("Expected first agent ID %q, got %q", "cred-1", agents[0].ID)
	}

	// Verify issuedAt is mapped to CreatedAt
	if agents[0].CreatedAt != 1700000000000 {
		t.Errorf("Expected CreatedAt %d, got %d", 1700000000000, agents[0].CreatedAt)
	}

	if agents[0].LastVerifiedAt != 1700001000000 {
		t.Errorf("Expected LastVerifiedAt %d, got %d", 1700001000000, agents[0].LastVerifiedAt)
	}

	if agents[1].AgentName != "agent-2" {
		t.Errorf("Expected second agent AgentName %q, got %q", "agent-2", agents[1].AgentName)
	}

	if agents[1].LastVerifiedAt != 0 {
		t.Errorf("Expected zero LastVerifiedAt for second agent, got %d", agents[1].LastVerifiedAt)
	}
}

func TestDeleteAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("Expected DELETE request, got %s", r.Method)
		}

		if r.URL.Path != "/credentials/cred-123" {
			t.Errorf("Expected /credentials/cred-123 path, got %s", r.URL.Path)
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-api-key" {
			t.Errorf("Expected Authorization header %q, got %q", "Bearer test-api-key", authHeader)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &TetherClient{
		apiKey:     "test-api-key",
		baseURL:    server.URL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	ctx := context.Background()
	ok, err := client.DeleteAgent(ctx, "cred-123")
	if err != nil {
		t.Fatalf("Failed to delete agent: %v", err)
	}

	if !ok {
		t.Error("Expected delete to return true")
	}
}

func TestAgentMethodsRequireApiKey(t *testing.T) {
	client := &TetherClient{
		credentialID: "test-credential",
		httpClient:   &http.Client{Timeout: 5 * time.Second},
	}

	ctx := context.Background()

	// CreateAgent
	_, err := client.CreateAgent(ctx, "agent", "desc")
	if err == nil {
		t.Error("Expected error for CreateAgent without API key")
	}
	if !strings.Contains(err.Error(), "API key is required") {
		t.Errorf("Expected 'API key is required' error, got: %v", err)
	}

	// ListAgents
	_, err = client.ListAgents(ctx)
	if err == nil {
		t.Error("Expected error for ListAgents without API key")
	}
	if !strings.Contains(err.Error(), "API key is required") {
		t.Errorf("Expected 'API key is required' error, got: %v", err)
	}

	// DeleteAgent
	_, err = client.DeleteAgent(ctx, "cred-123")
	if err == nil {
		t.Error("Expected error for DeleteAgent without API key")
	}
	if !strings.Contains(err.Error(), "API key is required") {
		t.Errorf("Expected 'API key is required' error, got: %v", err)
	}
}

func TestDeleteAgentHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &TetherClient{
		apiKey:     "test-api-key",
		baseURL:    server.URL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	ctx := context.Background()
	ok, err := client.DeleteAgent(ctx, "nonexistent")
	if err == nil {
		t.Error("Expected error for HTTP 404")
	}

	if ok {
		t.Error("Expected delete to return false on error")
	}

	apiErr, isAPIErr := err.(*APIError)
	if !isAPIErr {
		t.Errorf("Expected APIError, got %T", err)
	} else if apiErr.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status code %d, got %d", http.StatusNotFound, apiErr.StatusCode)
	}
}