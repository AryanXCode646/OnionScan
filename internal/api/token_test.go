package api

import (
	"encoding/hex"
	"errors"
	"testing"
)

type failingReader struct{}

func (f *failingReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("entropy source failure")
}

func TestGenerateToken_Valid(t *testing.T) {
	token1, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if len(token1) != 64 {
		t.Errorf("expected 64 hex characters (32 bytes entropy), got len=%d", len(token1))
	}

	bytes1, err := hex.DecodeString(token1)
	if err != nil {
		t.Fatalf("token is not valid hex: %v", err)
	}
	if len(bytes1) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(bytes1))
	}

	// Successive tokens must differ
	token2, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken second call failed: %v", err)
	}
	if token1 == token2 {
		t.Errorf("successive generated tokens must not be identical: %q == %q", token1, token2)
	}
}

func TestGenerateTokenFromReader_Error(t *testing.T) {
	token, err := GenerateTokenFromReader(&failingReader{})
	if err == nil {
		t.Errorf("expected error from failing entropy source, got nil")
	}
	if token != "" {
		t.Errorf("expected empty token on error, got %q", token)
	}
}
