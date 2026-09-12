package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// GenerateToken creates a cryptographically secure random token (32 bytes hex-encoded, 256-bit entropy).
func GenerateToken() (string, error) {
	return GenerateTokenFromReader(rand.Reader)
}

// GenerateTokenFromReader creates a random token reading from the provided entropy source.
func GenerateTokenFromReader(r io.Reader) (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("generate secure token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
