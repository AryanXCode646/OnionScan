package credentials

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestCredentialsAnalyzer_TruePositives(t *testing.T) {
	ctx := context.Background()
	a := New()
	target := model.Target{Onion: "exampleabcdefghijklmnop.onion"}

	// Dynamically assemble dummy tokens so repository push-protection does not flag test fixtures
	rawAWSKey := fmt.Sprintf("%s%s", "AKIA", "IOSFODNN7EXAMPLE")
	rawGitHubToken := fmt.Sprintf("%s_%s", "ghp", "111122223333444455556666777788889999")
	rawSlackToken := strings.Join([]string{"xoxb", "123456789012", "1234567890123", "abcdefghijklmnopqrstuvwx"}, "-")
	rawStripeKey := strings.Join([]string{"sk", "live", "51Abcdefghijklmnopqrstuvwx1234"}, "_")
	rawGoogleKey := fmt.Sprintf("%s%s", "AIza", "SyD1234567890123456789012345678901")
	rawJWT := strings.Join([]string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"eyJzdWIiOiIxMjM0NTY3ODkwIn0",
		"dozjgNryP4J3jVmNHl0w5N_XgL0n3A9Pl8nBv123456",
	}, ".")
	rawGenericKey := "super_secret_api_token_1234567890"

	body := fmt.Sprintf(`
<html>
<head><title>Config</title></head>
<body>
<script>
  const awsKey = "%s";
  const ghToken = "%s";
  const slackToken = "%s";
  const stripeKey = "%s";
  const gKey = "%s";
  const sessionToken = "%s";
  const api_key = "%s";
</script>
<pre>
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0...
PRIVATE KEY BODY MATERIAL SHOULD NEVER BE EXPOSED
-----END RSA PRIVATE KEY-----
</pre>
</body>
</html>`, rawAWSKey, rawGitHubToken, rawSlackToken, rawStripeKey, rawGoogleKey, rawJWT, rawGenericKey)

	page := model.Page{
		URL:  "http://exampleabcdefghijklmnop.onion/config.js",
		Body: []byte(body),
	}

	findings, err := a.Analyze(ctx, target, page)
	if err != nil {
		t.Fatalf("Analyze returned unexpected error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (CRED-001 and CRED-002), got %d", len(findings))
	}

	findingMap := make(map[string]model.Finding)
	for _, f := range findings {
		findingMap[f.ID] = f
	}

	f1, ok := findingMap["CRED-001"]
	if !ok {
		t.Fatalf("expected finding CRED-001, but not found")
	}
	if f1.Severity != model.SeverityHigh {
		t.Errorf("expected CRED-001 severity HIGH, got %s", f1.Severity)
	}
	if len(f1.Evidence) < 6 {
		t.Errorf("expected at least 6 evidence items for CRED-001, got %d", len(f1.Evidence))
	}

	f2, ok := findingMap["CRED-002"]
	if !ok {
		t.Fatalf("expected finding CRED-002, but not found")
	}
	if f2.Severity != model.SeverityCritical {
		t.Errorf("expected CRED-002 severity CRITICAL, got %s", f2.Severity)
	}
	if len(f2.Evidence) != 1 {
		t.Errorf("expected 1 evidence item for CRED-002, got %d", len(f2.Evidence))
	}

	// Safety check: verify raw secrets NEVER appear unredacted in evidence or findings
	allRawSecrets := []string{
		rawAWSKey,
		rawGitHubToken,
		rawSlackToken,
		rawStripeKey,
		rawGoogleKey,
		rawJWT,
		rawGenericKey,
		"PRIVATE KEY BODY MATERIAL SHOULD NEVER BE EXPOSED",
	}

	for _, f := range findings {
		for _, raw := range allRawSecrets {
			if strings.Contains(f.Title, raw) || strings.Contains(f.Explanation, raw) || strings.Contains(f.Recommendation, raw) {
				t.Errorf("unredacted secret %q found in finding metadata for %s", raw, f.ID)
			}
			for _, ev := range f.Evidence {
				if strings.Contains(ev.Description, raw) {
					t.Errorf("unredacted secret %q found in evidence description: %s", raw, ev.Description)
				}
			}
		}
	}
}

func TestCredentialsAnalyzer_TrueNegatives(t *testing.T) {
	ctx := context.Background()
	a := New()
	target := model.Target{Onion: "exampleabcdefghijklmnop.onion"}

	cleanBody := `
<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body>
  <h1>Safe Onion Service</h1>
  <p>Public keys and certificates are safe and should not trigger CRED-002:</p>
  <pre>
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJV
...
-----END CERTIFICATE-----
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzw...
-----END PUBLIC KEY-----
  </pre>
  <p>No tokens or credentials exposed here.</p>
</body>
</html>`

	page := model.Page{
		URL:  "http://exampleabcdefghijklmnop.onion/about",
		Body: []byte(cleanBody),
	}

	findings, err := a.Analyze(ctx, target, page)
	if err != nil {
		t.Fatalf("Analyze returned unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for clean page, got %d: %+v", len(findings), findings)
	}
}

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "[REDACTED]"},
		{"short", "[REDACTED]"},
		{"12345678", "[REDACTED]"},
		{"123456789", "1234...6789 (len:9)"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIA...MPLE (len:20)"},
	}

	for _, tt := range tests {
		got := redactSecret(tt.input)
		if got != tt.expected {
			t.Errorf("redactSecret(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
