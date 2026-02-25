package tether

import "errors"

// ErrVerification indicates a verification failure
var ErrVerification = errors.New("verification failed")

// ErrAPI indicates an API communication error
var ErrAPI = errors.New("API error")

// ErrKeyLoad indicates a private key loading error
var ErrKeyLoad = errors.New("key load error")

// VerificationError represents a verification failure with details
type VerificationError struct {
	Message string
	Err     error
}

func (e *VerificationError) Error() string {
	if e.Err != nil {
		return "verification failed: " + e.Message + ": " + e.Err.Error()
	}
	return "verification failed: " + e.Message
}

func (e *VerificationError) Unwrap() error {
	return e.Err
}

// APIError represents an API communication error
type APIError struct {
	StatusCode int
	Message    string
	Err        error
}

func (e *APIError) Error() string {
	if e.Err != nil {
		return "API error: " + e.Message + ": " + e.Err.Error()
	}
	return "API error: " + e.Message
}

func (e *APIError) Unwrap() error {
	return e.Err
}

// KeyLoadError represents a private key loading error
type KeyLoadError struct {
	Message string
	Err     error
}

func (e *KeyLoadError) Error() string {
	if e.Err != nil {
		return "key load error: " + e.Message + ": " + e.Err.Error()
	}
	return "key load error: " + e.Message
}

func (e *KeyLoadError) Unwrap() error {
	return e.Err
}