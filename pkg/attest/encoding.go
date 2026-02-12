package attest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Tributary-ai-services/Gatekeeper/pkg/types"
)

// EncodeAttestation serializes an attestation to a base64-encoded JSON string
// suitable for HTTP header propagation.
func EncodeAttestation(a *types.Attestation) (string, error) {
	if a == nil {
		return "", fmt.Errorf("attestation is nil")
	}

	data, err := json.Marshal(a)
	if err != nil {
		return "", fmt.Errorf("failed to marshal attestation: %w", err)
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

// DecodeAttestation deserializes an attestation from a base64-encoded JSON string
// typically received from an HTTP header.
func DecodeAttestation(s string) (*types.Attestation, error) {
	if s == "" {
		return nil, fmt.Errorf("attestation string is empty")
	}

	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 attestation: %w", err)
	}

	var a types.Attestation
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation: %w", err)
	}

	return &a, nil
}
