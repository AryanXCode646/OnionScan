package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestDefaultDataDir verifies that defaultDataDir honors ONIONSEC_DATA_DIR
// and falls back to user home directory when the env var is not set.
func TestDefaultDataDir(t *testing.T) {
	// 1. When ONIONSEC_DATA_DIR is explicitly set, it must take precedence.
	customPath := filepath.Join(t.TempDir(), "custom.db")
	t.Setenv("ONIONSEC_DATA_DIR", customPath)
	if got := defaultDataDir(); got != customPath {
		t.Errorf("defaultDataDir() with env set = %q, want %q", got, customPath)
	}

	// 2. When ONIONSEC_DATA_DIR is empty, fallback should be ~/.onionsec/onionsec.db.
	t.Setenv("ONIONSEC_DATA_DIR", "")
	fallback := defaultDataDir()
	if !strings.HasSuffix(filepath.ToSlash(fallback), ".onionsec/onionsec.db") {
		t.Errorf("defaultDataDir() fallback = %q, expected suffix '.onionsec/onionsec.db'", fallback)
	}
}

// getFreeLocalAddr finds an available TCP port on 127.0.0.1.
func getFreeLocalAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free local address: %v", err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// TestOnionsecd_SmokeTest exercises the CLI startup and graceful shutdown
// of onionsecd as a subprocess with explicit flags.
func TestOnionsecd_SmokeTest(t *testing.T) {
	tempDir := t.TempDir()
	binPath := filepath.Join(tempDir, "onionsecd_test_bin")
	dbPath := filepath.Join(tempDir, "test.db")

	// Build the daemon binary for testing
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Dir = "."
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build onionsecd binary: %v\nOutput: %s", err, string(out))
	}

	addr := getFreeLocalAddr(t)

	// Start daemon with test flags
	cmd := exec.Command(
		binPath,
		"-addr", addr,
		"-db", dbPath,
		"-socks", "127.0.0.1:19050",
	)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start onionsecd subprocess: %v", err)
	}

	// Ensure cleanup in all cases
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})

	// Wait for daemon HTTP listener to become reachable
	healthURL := fmt.Sprintf("http://%s/healthz", addr)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	started := false
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		resp, err := client.Get(healthURL)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				started = true
				_ = body
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !started {
		t.Fatalf("onionsecd failed to become reachable at %s within 5s\nStdout: %s\nStderr: %s",
			healthURL, stdoutBuf.String(), stderrBuf.String())
	}

	// Send SIGTERM to initiate graceful shutdown
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM to onionsecd: %v", err)
	}

	// Wait for process to exit cleanly
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("onionsecd exited with error: %v\nStderr: %s", err, stderrBuf.String())
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("onionsecd timed out waiting for graceful shutdown after SIGTERM")
	}

	// Verify startup and shutdown output
	stdoutStr := stdoutBuf.String()
	if !strings.Contains(stdoutStr, "onionsecd listening on") {
		t.Errorf("expected stdout to contain 'onionsecd listening on', got: %q", stdoutStr)
	}
	if !strings.Contains(stdoutStr, "shutting down onionsecd") {
		t.Errorf("expected stdout to contain 'shutting down onionsecd', got: %q", stdoutStr)
	}

	// Verify SQLite database file was created
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("expected sqlite db file %q to be created, stat err: %v", dbPath, err)
	}
}
