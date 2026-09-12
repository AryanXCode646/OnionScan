package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestRunScan_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	var stdout, stderr bytes.Buffer
	err := runScan(ctx, []string{"testtarget.onion"}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected error from cancelled context, got nil")
	}

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled error, got: %v", err)
	}
}
