package tether

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const (
	// DefaultBaseURL is the default Tether API base URL
	DefaultBaseURL = "https://api.tether.name"
	
	// UserAgent for HTTP requests
	UserAgent = "tether-go/1.0.0"
)

// TetherClient represents a client for the Tether API
type TetherClient struct {
	credentialID string
	privateKey   *rsa.PrivateKey
	baseURL      string
	httpClient   *http.Client
}

// NewClient creates a new TetherClient with the given options
func NewClient(opts Options) (*TetherClient, error) {
	// Get credential ID from options or environment
	credentialID := opts.CredentialID
	if credentialID == "" {
		credentialID = os.Getenv("TETHER_CREDENTIAL_ID")
	}
	if credentialID == "" {
		return nil, &KeyLoadError{
			Message: "credential ID is required",
			Err:     ErrKeyLoad,
		}
	}
	
	// Handle private key path from environment if not provided
	optsWithEnv := opts
	if optsWithEnv.PrivateKeyPath == "" && len(optsWithEnv.PrivateKeyPEM) == 0 && len(optsWithEnv.PrivateKeyDER) == 0 {
		if envPath := os.Getenv("TETHER_PRIVATE_KEY_PATH"); envPath != "" {
			optsWithEnv.PrivateKeyPath = envPath
		}
	}
	
	// Load private key
	privateKey, err := loadPrivateKey(optsWithEnv)
	if err != nil {
		return nil, err
	}
	
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	
	return &TetherClient{
		credentialID: credentialID,
		privateKey:   privateKey,
		baseURL:      baseURL,
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

// Sign signs a challenge using the client's private key
func (c *TetherClient) Sign(challenge string) (string, error) {
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

// SubmitProof submits a signed challenge proof for verification
func (c *TetherClient) SubmitProof(ctx context.Context, challenge, proof string) (*VerificationResult, error) {
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