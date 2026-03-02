# tether-go

[![Go Reference](https://pkg.go.dev/badge/github.com/tether-name/tether-name-go.svg)](https://pkg.go.dev/github.com/tether-name/tether-name-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/tether-name/tether-name-go)](https://goreportcard.com/report/github.com/tether-name/tether-name-go)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Go client library for [Tether](https://tether.name) - cryptographic identity verification for AI agents. Tether lets AI agents prove their identity using RSA digital signatures, and manage agents programmatically with API keys.

## Installation

```bash
go get github.com/tether-name/tether-name-go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/tether-name/tether-name-go"
)

func main() {
    // Initialize client with agent ID and private key
    client, err := tether.NewClient(tether.Options{
        AgentID:   "your-agent-id",
        PrivateKeyPath: "/path/to/private-key.pem",
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

## Agent Management

Use an API key to create, list, and delete agents programmatically:

```go
client, err := tether.NewClient(tether.Options{
    ApiKey: "sk-tether-name-...",
})
if err != nil {
    log.Fatal(err)
}

ctx := context.Background()

// Create a new agent
agent, err := client.CreateAgent(ctx, "my-bot", "My AI assistant")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Created agent: %s (ID: %s)\n", agent.AgentName, agent.ID)

// Create an agent with a verified domain
domains, err := client.ListDomains(ctx)
if err != nil {
    log.Fatal(err)
}
if len(domains) > 0 && domains[0].Verified {
    agent, err := client.CreateAgent(ctx, "my-bot", "My AI assistant", domains[0].ID)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Created agent with domain: %s\n", agent.AgentName)
}

// List all agents
agents, err := client.ListAgents(ctx)
if err != nil {
    log.Fatal(err)
}
for _, a := range agents {
    fmt.Printf("  %s (%s)\n", a.AgentName, a.ID)
}

// Delete an agent
deleted, err := client.DeleteAgent(ctx, agent.ID)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Deleted: %t\n", deleted)
```

When using an API key, `AgentID` and private key options become optional — they're only needed for verify/sign operations.

## Step-by-Step Verification

For more control over the verification process:

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/tether-name/tether-name-go"
)

func main() {
    client, err := tether.NewClient(tether.Options{
        AgentID:   "your-agent-id",
        PrivateKeyPath: "/path/to/private-key.pem",
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

### Full Options
```go
client, err := tether.NewClient(tether.Options{
    AgentID:   "your-agent-id",
    PrivateKeyPath: "/path/to/key.pem",              // PEM or DER format
    ApiKey:         "sk-tether-name-...",                 // Optional, for agent management
})
```

### PEM Bytes
```go
pemData := []byte(`-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----`)

client, err := tether.NewClient(tether.Options{
    AgentID:  "your-agent-id",
    PrivateKeyPEM: pemData,
})
```

### DER Bytes
```go
client, err := tether.NewClient(tether.Options{
    AgentID:  "your-agent-id",
    PrivateKeyDER: derBytes, // Raw DER-encoded key bytes
})
```

## Environment Variables

You can use environment variables as fallbacks:

```bash
export TETHER_AGENT_ID="your-agent-id"
export TETHER_PRIVATE_KEY_PATH="/path/to/private-key.pem"
export TETHER_API_KEY="sk-tether-name-..."
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
- `AgentID` (string): Your unique agent agent ID (required for verify/sign, optional with API key)
- `PrivateKeyPath` (string): Path to RSA private key file (PEM or DER format)
- `PrivateKeyPEM` ([]byte): RSA private key in PEM format
- `PrivateKeyDER` ([]byte): RSA private key in DER format
- `ApiKey` (string): API key for agent management (falls back to `TETHER_API_KEY` env var)

### Client Methods

#### `Verify(ctx context.Context) (*VerificationResult, error)`
Performs complete verification flow: requests challenge, signs it, and submits proof.

#### `RequestChallenge(ctx context.Context) (string, error)`
Requests a new challenge from the Tether API.

#### `Sign(challenge string) (string, error)`
Signs a challenge using the client's private key. Returns URL-safe base64 signature (no padding).

#### `SubmitProof(ctx context.Context, challenge, proof string) (*VerificationResult, error)`
Submits signed challenge proof for verification.

#### `CreateAgent(ctx context.Context, agentName, description string, domainID ...string) (*Agent, error)`
Creates a new agent. Optionally pass a verified domain ID. Requires an API key.

#### `ListAgents(ctx context.Context) ([]Agent, error)`
Lists all agents for the authenticated user. Requires an API key.

#### `DeleteAgent(ctx context.Context, agentID string) (bool, error)`
Deletes an agent by ID. Requires an API key.

#### `ListDomains(ctx context.Context) ([]Domain, error)`
Lists all registered domains for the authenticated user. Requires an API key.

### Types

#### `VerificationResult`

Result returned by `Verify`, `RequestChallenge`, and `SubmitProof`.

| Field | Type | Description |
|-------|------|-------------|
| `Verified` | `bool` | Whether verification succeeded |
| `AgentName` | `string` | Registered agent name |
| `VerifyURL` | `string` | Public verification URL |
| `Email` | `string` | Registered owner email |
| `Domain` | `string` | Verified domain (if assigned to this agent) |
| `RegisteredSince` | `*EpochTime` | Registration timestamp |
| `Error` | `string` | Error message if verification failed |
| `Challenge` | `string` | The verified challenge code |

```go
type VerificationResult struct {
    Verified        bool       `json:"verified"`
    AgentName       string     `json:"agentName,omitempty"`
    VerifyURL       string     `json:"verifyUrl,omitempty"`
    Email           string     `json:"email,omitempty"`
    Domain          string     `json:"domain,omitempty"`
    RegisteredSince *EpochTime `json:"registeredSince,omitempty"`
    Error           string     `json:"error,omitempty"`
    Challenge       string     `json:"challenge,omitempty"`
}
```

#### `Agent`

Agent returned by management operations.

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | Unique agent ID |
| `AgentName` | `string` | Agent display name |
| `Description` | `string` | Agent description |
| `DomainID` | `string` | Assigned domain ID (if any) |
| `Domain` | `string` | Assigned domain name (if any) |
| `CreatedAt` | `int64` | Creation time (epoch ms) |
| `RegistrationToken` | `string` | Token for key registration (returned on create) |
| `LastVerifiedAt` | `int64` | Last verification time (epoch ms) |

```go
type Agent struct {
    ID                string `json:"id"`
    AgentName         string `json:"agentName"`
    Description       string `json:"description"`
    DomainID          string `json:"domainId,omitempty"`
    Domain            string `json:"domain,omitempty"`
    CreatedAt         int64  `json:"createdAt"`
    RegistrationToken string `json:"registrationToken,omitempty"`
    LastVerifiedAt    int64  `json:"lastVerifiedAt,omitempty"`
}
```

#### `Domain`

Domain returned by `ListDomains`.

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | Unique domain ID |
| `Domain` | `string` | Domain name |
| `Verified` | `bool` | Whether the domain is verified |
| `VerifiedAt` | `int64` | Verification time (epoch ms) |
| `LastCheckedAt` | `int64` | Last re-verification check (epoch ms) |
| `CreatedAt` | `int64` | Creation time (epoch ms) |

```go
type Domain struct {
    ID            string `json:"id"`
    Domain        string `json:"domain"`
    Verified      bool   `json:"verified"`
    VerifiedAt    int64  `json:"verifiedAt,omitempty"`
    LastCheckedAt int64  `json:"lastCheckedAt,omitempty"`
    CreatedAt     int64  `json:"createdAt,omitempty"`
}
```

### Error Types

The library provides custom error types for different failure scenarios:
- `VerificationError`: Verification failed (invalid signature, etc.)
- `APIError`: Network or HTTP errors
- `KeyLoadError`: Private key loading errors

## How Tether Works

1. **Registration**: Register your AI agent at [tether.name](https://tether.name) to get a agent ID and generate an RSA key pair
2. **Challenge**: Request a unique challenge code from the Tether API
3. **Signature**: Sign the challenge with your private key using SHA256withRSA
4. **Verification**: Submit the challenge and signature for verification
5. **Proof**: Receive verification result with public verify URL

## Requirements

- Go 1.22 or later
- RSA-2048 private key (PEM or DER format)
- No external dependencies (uses only Go standard library)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Publishing

Go modules are published via git tags — no registry upload needed.

### Version checklist

Update the version in:

1. `client.go` → `UserAgent` constant

### Steps

1. Update the UserAgent version string above
2. Commit and push to `main`
3. Tag the release: `git tag v1.0.0 && git push --tags`
4. The module is immediately available via `go get github.com/tether-name/tether-name-go@v1.0.0`

## Links

- 🌐 [Tether Website](https://tether.name)
- 📘 [Documentation](https://docs.tether.name)
- 📦 [pkg.go.dev](https://pkg.go.dev/github.com/tether-name/tether-name-go)
- 💻 [GitHub](https://github.com/tether-name/tether-name-go)