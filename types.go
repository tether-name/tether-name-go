package tether

import (
	"encoding/json"
	"fmt"
	"time"
)

// EpochTime wraps time.Time to handle both epoch millisecond integers
// and ISO 8601 strings when unmarshaling JSON.
type EpochTime struct {
	time.Time
}

// UnmarshalJSON handles epoch ms (number) or ISO 8601 (string).
func (et *EpochTime) UnmarshalJSON(data []byte) error {
	// Try as number first (epoch milliseconds)
	var ms float64
	if err := json.Unmarshal(data, &ms); err == nil {
		sec := int64(ms) / 1000
		nsec := (int64(ms) % 1000) * int64(time.Millisecond)
		et.Time = time.Unix(sec, nsec).UTC()
		return nil
	}

	// Try as string (ISO 8601)
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return fmt.Errorf("cannot parse time string %q: %w", s, err)
		}
		et.Time = t
		return nil
	}

	return fmt.Errorf("cannot unmarshal %s as time", string(data))
}

// MarshalJSON outputs as epoch milliseconds for round-trip consistency.
func (et EpochTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(et.UnixMilli())
}

// Options configures the TetherClient
type Options struct {
	// AgentID is the unique identifier for this agent (required for verify/sign operations)
	AgentID string

	// PrivateKeyPath is the file path to the RSA private key (PEM or DER format)
	PrivateKeyPath string

	// PrivateKeyPEM contains the RSA private key in PEM format as bytes
	PrivateKeyPEM []byte

	// PrivateKeyDER contains the RSA private key in DER format as bytes
	PrivateKeyDER []byte


	// ApiKey for management operations (alternative to agent auth)
	ApiKey string
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
	RegisteredSince *EpochTime `json:"registeredSince,omitempty"`
	
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
	AgentID string `json:"agentId"`
}

// VerifyResponse represents the response from challenge verification
type verifyResponse struct {
	Valid           bool       `json:"valid"`
	VerifyURL       string     `json:"verifyUrl,omitempty"`
	AgentName       string     `json:"agentName,omitempty"`
	Email           string     `json:"email,omitempty"`
	RegisteredSince *EpochTime `json:"registeredSince,omitempty"`
	Error           string     `json:"error,omitempty"`
}

// Agent represents a registered agent
type Agent struct {
	ID                string `json:"id"`
	AgentName         string `json:"agentName"`
	Description       string `json:"description"`
	CreatedAt         int64  `json:"createdAt"`
	RegistrationToken string `json:"registrationToken,omitempty"`
	LastVerifiedAt    int64  `json:"lastVerifiedAt,omitempty"`
}

// issueAgentRequest is the request payload for the /agents/issue endpoint
type issueAgentRequest struct {
	AgentName   string `json:"agentName"`
	Description string `json:"description,omitempty"`
}

// issueAgentResponse is the response payload from the /agents/issue endpoint
type issueAgentResponse struct {
	ID                string `json:"id"`
	AgentName         string `json:"agentName"`
	Description       string `json:"description"`
	CreatedAt         int64  `json:"createdAt"`
	RegistrationToken string `json:"registrationToken"`
}

// listAgentEntry is the API response shape for /agents, where createdAt is "issuedAt"
type listAgentEntry struct {
	ID             string `json:"id"`
	AgentName      string `json:"agentName"`
	Description    string `json:"description"`
	IssuedAt       int64  `json:"issuedAt"`
	LastVerifiedAt int64  `json:"lastVerifiedAt,omitempty"`
}