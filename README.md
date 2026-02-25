# tether-go

[![Go Reference](https://pkg.go.dev/badge/github.com/Commit451/tether-name-go.svg)](https://pkg.go.dev/github.com/Commit451/tether-name-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/Commit451/tether-name-go)](https://goreportcard.com/report/github.com/Commit451/tether-name-go)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Go client library for [Tether](https://tether.name) - cryptographic identity verification for AI agents. Tether lets AI agents prove their identity using RSA digital signatures, enabling secure verification of agent authenticity.

## Installation

```bash
go get github.com/Commit451/tether-name-go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/Commit451/tether-name-go"
)

func main() {
    // Initialize client with credential ID and private key
    client, err := tether.NewClient(tether.Options{
        CredentialID:   "your-credential-id",
        PrivateKeyPath: "/path/to/your/private-key.pem",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // Verify agent identity
    result, err := client.Verify(context.Background())
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Verified: %t\n", result.Verified)
    fmt.Printf("Agent: %s\n", result.AgentName)
    fmt.Printf("Verify URL: %s\n", result.VerifyURL)
}
```

## Step-by-Step Verification

For more control over the verification process:

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/Commit451/tether-name-go"
)

func main() {
    client, err := tether.NewClient(tether.Options{
        CredentialID:   "your-credential-id",
        PrivateKeyPath: "/path/to/your/private-key.pem",
    })
    if err != nil {
        log.Fatal(err)
    }
    
    ctx := context.Background()
    
    // Step 1: Request a challenge
    challenge, err := client.RequestChallenge(ctx)
    if err != nil {
        log.Fatal("Failed to request challenge:", err)
    }
    fmt.Printf("Challenge: %s\n", challenge)
    
    // Step 2: Sign the challenge
    proof, err := client.Sign(challenge)
    if err != nil {
        log.Fatal("Failed to sign challenge:", err)
    }
    fmt.Printf("Proof: %s\n", proof)
    
    // Step 3: Submit proof for verification
    result, err := client.SubmitProof(ctx, challenge, proof)
    if err != nil {
        log.Fatal("Failed to verify proof:", err)
    }
    
    fmt.Printf("Verification Result:\n")
    fmt.Printf("  Verified: %t\n", result.Verified)
    fmt.Printf("  Agent: %s\n", result.AgentName)
    fmt.Printf("  Email: %s\n", result.Email)
    fmt.Printf("  Verify URL: %s\n", result.VerifyURL)
    if result.RegisteredSince != nil {
        fmt.Printf("  Registered: %s\n", result.RegisteredSince.Format("2006-01-02"))
    }
}
```

## Private Key Formats

The library supports multiple ways to provide your RSA private key:

### File Path
```go
client, err := tether.NewClient(tether.Options{
    CredentialID:   "your-credential-id",
    PrivateKeyPath: "/path/to/key.pem", // PEM or DER format
})
```

### PEM Bytes
```go
pemData := []byte(`-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----`)

client, err := tether.NewClient(tether.Options{
    CredentialID:  "your-credential-id",
    PrivateKeyPEM: pemData,
})
```

### DER Bytes
```go
client, err := tether.NewClient(tether.Options{
    CredentialID:  "your-credential-id",
    PrivateKeyDER: derBytes, // Raw DER-encoded key bytes
})
```

## Environment Variables

You can use environment variables as fallbacks:

```bash
export TETHER_CREDENTIAL_ID="your-credential-id"
export TETHER_PRIVATE_KEY_PATH="/path/to/your/private-key.pem"
```

```go
// Will use environment variables if options are empty
client, err := tether.NewClient(tether.Options{})
```

## API Reference

### Client Creation

#### `NewClient(opts Options) (*TetherClient, error)`
Creates a new Tether client with the specified options.

**Options:**
- `CredentialID` (string): Your unique agent credential ID (required)
- `PrivateKeyPath` (string): Path to RSA private key file (PEM/DER format)
- `PrivateKeyPEM` ([]byte): RSA private key in PEM format
- `PrivateKeyDER` ([]byte): RSA private key in DER format

### Client Methods

#### `Verify(ctx context.Context) (*VerificationResult, error)`
Performs complete verification flow: requests challenge, signs it, and submits proof.

#### `RequestChallenge(ctx context.Context) (string, error)`
Requests a new challenge from the Tether API.

#### `Sign(challenge string) (string, error)`
Signs a challenge using the client's private key. Returns URL-safe base64 signature (no padding).

#### `SubmitProof(ctx context.Context, challenge, proof string) (*VerificationResult, error)`
Submits signed challenge proof for verification.

### Types

#### `VerificationResult`
```go
type VerificationResult struct {
    Verified        bool       `json:"verified"`
    AgentName       string     `json:"agentName,omitempty"`
    VerifyURL       string     `json:"verifyUrl,omitempty"`
    Email           string     `json:"email,omitempty"`
    RegisteredSince *time.Time `json:"registeredSince,omitempty"`
    Error           string     `json:"error,omitempty"`
    Challenge       string     `json:"challenge,omitempty"`
}
```

### Error Types

The library provides custom error types for different failure scenarios:
- `VerificationError`: Verification failed (invalid signature, etc.)
- `APIError`: Network or HTTP errors
- `KeyLoadError`: Private key loading errors

## How Tether Works

1. **Registration**: Register your AI agent at [tether.name](https://tether.name) to get a credential ID and generate an RSA key pair
2. **Challenge**: Request a unique challenge code from the Tether API
3. **Signature**: Sign the challenge with your private key using SHA256withRSA
4. **Verification**: Submit the challenge and signature for verification
5. **Proof**: Receive verification result with public verify URL

## Requirements

- Go 1.21 or later
- RSA-2048 private key (PEM or DER format)
- No external dependencies (uses only Go standard library)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Learn More

Visit [tether.name](https://tether.name) to learn more about Tether and register your AI agent.