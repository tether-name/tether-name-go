package tether

import (
	"time"
)

// Options configures the TetherClient
type Options struct {
	// CredentialID is the unique identifier for this agent (required)
	CredentialID string
	
	// PrivateKeyPath is the file path to the RSA private key (PEM or DER format)
	PrivateKeyPath string
	
	// PrivateKeyPEM contains the RSA private key in PEM format as bytes
	PrivateKeyPEM []byte
	
	// PrivateKeyDER contains the RSA private key in DER format as bytes
	PrivateKeyDER []byte
}

// VerificationResult contains the result of a verification attempt
type VerificationResult struct {
	// Verified indicates if the agent identity was successfully verified
	Verified bool `json:"verified"`
	
	// AgentName is the registered name of the agent
	AgentName string `json:"agentName,omitempty"`
	
	// VerifyURL is the public URL to verify this challenge result
	VerifyURL string `json:"verifyUrl,omitempty"`
	
	// Email is the email address associated with the agent
	Email string `json:"email,omitempty"`
	
	// RegisteredSince is when this agent was first registered
	RegisteredSince *time.Time `json:"registeredSince,omitempty"`
	
	// Error contains any error message if verification failed
	Error string `json:"error,omitempty"`
	
	// Challenge is the challenge code that was verified
	Challenge string `json:"challenge,omitempty"`
}

// ChallengeResponse represents the response from requesting a challenge
type challengeResponse struct {
	Code string `json:"code"`
}

// VerifyRequest represents the request payload for challenge verification
type verifyRequest struct {
	Challenge    string `json:"challenge"`
	Proof        string `json:"proof"`
	CredentialID string `json:"credentialId"`
}

// VerifyResponse represents the response from challenge verification
type verifyResponse struct {
	Valid           bool       `json:"valid"`
	VerifyURL       string     `json:"verifyUrl,omitempty"`
	AgentName       string     `json:"agentName,omitempty"`
	Email           string     `json:"email,omitempty"`
	RegisteredSince *time.Time `json:"registeredSince,omitempty"`
	Error           string     `json:"error,omitempty"`
}