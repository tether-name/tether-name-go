package tether

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	// DefaultBaseURL is the default Tether API base URL
	DefaultBaseURL = "https://api.tether.name"
	
	// UserAgent for HTTP requests
	UserAgent = "tether-go/1.0.3"
)

// TetherClient represents a client for the Tether API
type TetherClient struct {
	credentialID string
	privateKey   *rsa.PrivateKey
	apiKey       string
	baseURL      string
	httpClient   *http.Client
}

// NewClient creates a new TetherClient with the given options.
// When ApiKey is provided, credentialID and privateKey become optional
// (only required for verify/sign operations).
func NewClient(opts Options) (*TetherClient, error) {
	// Get API key from options or environment
	apiKey := opts.ApiKey
	if apiKey == "" {
		apiKey = os.Getenv("TETHER_API_KEY")
	}

	// Get credential ID from options or environment
	credentialID := opts.CredentialID
	if credentialID == "" {
		credentialID = os.Getenv("TETHER_CREDENTIAL_ID")
	}

	// Without an API key, credential ID is required
	if apiKey == "" && credentialID == "" {
		return nil, &KeyLoadError{
			Message: "credential ID is required",
			Err:     ErrKeyLoad,
		}
	}

	// Try to load private key (optional when apiKey is provided)
	var privateKey *rsa.PrivateKey
	optsWithEnv := opts
	if optsWithEnv.PrivateKeyPath == "" && len(optsWithEnv.PrivateKeyPEM) == 0 && len(optsWithEnv.PrivateKeyDER) == 0 {
		if envPath := os.Getenv("TETHER_PRIVATE_KEY_PATH"); envPath != "" {
			optsWithEnv.PrivateKeyPath = envPath
		}
	}

	hasKeyMaterial := optsWithEnv.PrivateKeyPath != "" || len(optsWithEnv.PrivateKeyPEM) > 0 || len(optsWithEnv.PrivateKeyDER) > 0
	if hasKeyMaterial {
		key, err := loadPrivateKey(optsWithEnv)
		if err != nil {
			return nil, err
		}
		privateKey = key
	} else if apiKey == "" {
		// No API key and no key material — private key is required
		return nil, &KeyLoadError{
			Message: "private key is required (provide PrivateKeyPEM, PrivateKeyDER, or PrivateKeyPath)",
			Err:     ErrKeyLoad,
		}
	}


	return &TetherClient{
		credentialID: credentialID,
		privateKey:   privateKey,
		apiKey:       apiKey,
		baseURL:      DefaultBaseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// Verify performs a complete verification flow (request challenge + sign + verify)
func (c *TetherClient) Verify(ctx context.Context) (*VerificationResult, error) {
	// Request challenge
	challenge, err := c.RequestChallenge(ctx)
	if err != nil {
		return &VerificationResult{
			Verified: false,
			Error:    err.Error(),
		}, err
	}
	
	// Sign challenge
	proof, err := c.Sign(challenge)
	if err != nil {
		return &VerificationResult{
			Verified:  false,
			Error:     err.Error(),
			Challenge: challenge,
		}, err
	}
	
	// Submit proof and return result
	return c.SubmitProof(ctx, challenge, proof)
}

// RequestChallenge requests a new challenge from the Tether API
func (c *TetherClient) RequestChallenge(ctx context.Context) (string, error) {
	url := c.baseURL + "/challenge"
	
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return "", &APIError{
			Message: "failed to create request",
			Err:     err,
		}
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", &APIError{
			Message: "request failed",
			Err:     err,
		}
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", &APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
			Err:        ErrAPI,
		}
	}
	
	var challengeResp challengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challengeResp); err != nil {
		return "", &APIError{
			Message: "failed to decode response",
			Err:     err,
		}
	}
	
	if challengeResp.Code == "" {
		return "", &APIError{
			Message: "empty challenge code received",
			Err:     ErrAPI,
		}
	}
	
	return challengeResp.Code, nil
}

// Sign signs a challenge using the client's private key.
// Requires a private key to be configured.
func (c *TetherClient) Sign(challenge string) (string, error) {
	if c.privateKey == nil {
		return "", &VerificationError{
			Message: "private key is required for signing",
			Err:     ErrVerification,
		}
	}
	normalizedChallenge := normalizeChallenge(challenge)
	proof, err := signChallenge(c.privateKey, normalizedChallenge)
	if err != nil {
		return "", &VerificationError{
			Message: "failed to sign challenge",
			Err:     err,
		}
	}
	return proof, nil
}

// SubmitProof submits a signed challenge proof for verification.
// Requires credentialID to be configured.
func (c *TetherClient) SubmitProof(ctx context.Context, challenge, proof string) (*VerificationResult, error) {
	if c.credentialID == "" {
		return nil, &APIError{
			Message: "credential ID is required for verification",
			Err:     ErrAPI,
		}
	}

	url := c.baseURL + "/challenge/verify"

	verifyReq := verifyRequest{
		Challenge:    normalizeChallenge(challenge),
		Proof:        proof,
		CredentialID: c.credentialID,
	}
	
	reqBody, err := json.Marshal(verifyReq)
	if err != nil {
		return nil, &APIError{
			Message: "failed to marshal request",
			Err:     err,
		}
	}
	
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, &APIError{
			Message: "failed to create request",
			Err:     err,
		}
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &APIError{
			Message: "request failed",
			Err:     err,
		}
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
			Err:        ErrAPI,
		}
	}
	
	var verifyResp verifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&verifyResp); err != nil {
		return nil, &APIError{
			Message: "failed to decode response",
			Err:     err,
		}
	}
	
	result := &VerificationResult{
		Verified:        verifyResp.Valid,
		AgentName:       verifyResp.AgentName,
		VerifyURL:       verifyResp.VerifyURL,
		Email:           verifyResp.Email,
		RegisteredSince: verifyResp.RegisteredSince,
		Error:           verifyResp.Error,
		Challenge:       challenge,
	}
	
	if !verifyResp.Valid {
		errorMsg := "verification failed"
		if verifyResp.Error != "" {
			errorMsg = verifyResp.Error
		}
		return result, &VerificationError{
			Message: errorMsg,
			Err:     ErrVerification,
		}
	}

	return result, nil
}

// setAuthHeaders sets Authorization header on the request when an API key is configured.
func (c *TetherClient) setAuthHeaders(req *http.Request) {
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
}

// CreateAgent creates a new agent.
// Requires an API key to be configured.
func (c *TetherClient) CreateAgent(ctx context.Context, agentName string, description string) (*Agent, error) {
	if c.apiKey == "" {
		return nil, &APIError{
			Message: "API key is required for agent management",
			Err:     ErrAPI,
		}
	}

	url := c.baseURL + "/credentials/issue"

	issueReq := issueCredentialRequest{
		AgentName:   agentName,
		Description: description,
	}

	reqBody, err := json.Marshal(issueReq)
	if err != nil {
		return nil, &APIError{
			Message: "failed to marshal request",
			Err:     err,
		}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, &APIError{
			Message: "failed to create request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &APIError{
			Message: "request failed",
			Err:     err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
			Err:        ErrAPI,
		}
	}

	var issueResp issueCredentialResponse
	if err := json.NewDecoder(resp.Body).Decode(&issueResp); err != nil {
		return nil, &APIError{
			Message: "failed to decode response",
			Err:     err,
		}
	}

	return &Agent{
		ID:                issueResp.ID,
		AgentName:         issueResp.AgentName,
		Description:       issueResp.Description,
		CreatedAt:         issueResp.CreatedAt,
		RegistrationToken: issueResp.RegistrationToken,
	}, nil
}

// ListAgents lists all agents for the authenticated user.
// Requires an API key to be configured.
func (c *TetherClient) ListAgents(ctx context.Context) ([]Agent, error) {
	if c.apiKey == "" {
		return nil, &APIError{
			Message: "API key is required for agent management",
			Err:     ErrAPI,
		}
	}

	url := c.baseURL + "/credentials"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, &APIError{
			Message: "failed to create request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &APIError{
			Message: "request failed",
			Err:     err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
			Err:        ErrAPI,
		}
	}

	var entries []listCredentialEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, &APIError{
			Message: "failed to decode response",
			Err:     err,
		}
	}

	agents := make([]Agent, len(entries))
	for i, entry := range entries {
		agents[i] = Agent{
			ID:             entry.ID,
			AgentName:      entry.AgentName,
			Description:    entry.Description,
			CreatedAt:      entry.IssuedAt,
			LastVerifiedAt: entry.LastVerifiedAt,
		}
	}

	return agents, nil
}

// DeleteAgent deletes an agent by ID.
// Requires an API key to be configured.
func (c *TetherClient) DeleteAgent(ctx context.Context, agentID string) (bool, error) {
	if c.apiKey == "" {
		return false, &APIError{
			Message: "API key is required for agent management",
			Err:     ErrAPI,
		}
	}

	deleteURL := c.baseURL + "/credentials/" + url.PathEscape(agentID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", deleteURL, nil)
	if err != nil {
		return false, &APIError{
			Message: "failed to create request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, &APIError{
			Message: "request failed",
			Err:     err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, &APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
			Err:        ErrAPI,
		}
	}

	return true, nil
}