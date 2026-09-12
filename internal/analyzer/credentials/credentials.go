// Package credentials inspects page content and scripts for accidental disclosures
// of secrets, such as API keys, authentication tokens, and private key headers.
//
// Safety rule: never report full secret values. All findings and evidence descriptions
// must strictly redact tokens and private key material.
package credentials

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

var (
	awsKeyRe        = regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`)
	slackTokenRe    = regexp.MustCompile(`\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b`)
	githubPatRe     = regexp.MustCompile(`\b(gh[pousr]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b`)
	stripeKeyRe     = regexp.MustCompile(`\b((?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99})\b`)
	googleApiKeyRe  = regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`)
	jwtTokenRe      = regexp.MustCompile(`\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)
	genericSecretRe = regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{20,80})["']?`)
	pemPrivateKeyRe = regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]*PRIVATE KEY(?: BLOCK)?-----`)
)

type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return "credentials" }

func (a *Analyzer) Analyze(ctx context.Context, target model.Target, page model.Page) ([]model.Finding, error) {
	var findings []model.Finding
	now := time.Now()
	content := string(page.Body)

	// 1. Detect API keys and tokens (CRED-001)
	var credEvidence []model.Evidence

	addCredEvidence := func(kind, rawVal string) {
		redacted := redactSecret(rawVal)
		desc := fmt.Sprintf("%s: %s", kind, redacted)
		credEvidence = append(credEvidence, model.Evidence{
			Type:        model.EvidenceCredential,
			Description: desc,
			Source:      page.URL,
		})
	}

	for _, m := range awsKeyRe.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			addCredEvidence("AWS Access Key ID", m[1])
		}
	}
	for _, m := range slackTokenRe.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			addCredEvidence("Slack Token", m[1])
		}
	}
	for _, m := range githubPatRe.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			addCredEvidence("GitHub Personal Access Token", m[1])
		}
	}
	for _, m := range stripeKeyRe.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			addCredEvidence("Stripe Key", m[1])
		}
	}
	for _, m := range googleApiKeyRe.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			addCredEvidence("Google API Key", m[1])
		}
	}
	for _, m := range jwtTokenRe.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			addCredEvidence("JSON Web Token (JWT)", m[1])
		}
	}
	for _, m := range genericSecretRe.FindAllStringSubmatch(content, -1) {
		if len(m) > 2 {
			label := strings.ToLower(strings.TrimSpace(m[1]))
			addCredEvidence(fmt.Sprintf("Secret assignment (%s)", label), m[2])
		}
	}

	credEvidence = dedupeEvidence(credEvidence)
	if len(credEvidence) > 0 {
		if len(credEvidence) > 20 {
			credEvidence = credEvidence[:20]
		}
		findings = append(findings, model.Finding{
			ID:             "CRED-001",
			Title:          "API key or token pattern disclosed",
			Severity:       model.SeverityHigh,
			Confidence:     0.90,
			Target:         target.Onion,
			Analyzer:       a.Name(),
			Evidence:       credEvidence,
			Explanation:    "An API key, access token, or credential pattern was discovered in page content or JavaScript. Hardcoded or leaked credentials can allow unauthorized access to external cloud providers, internal services, or databases.",
			Recommendation: "Immediately revoke and rotate the exposed credential. Remove all secret keys and tokens from client-side scripts, templates, and publicly served files.",
			CreatedAt:      now,
		})
	}

	// 2. Detect PEM private key headers (CRED-002)
	var privKeyEvidence []model.Evidence
	for _, m := range pemPrivateKeyRe.FindAllString(content, -1) {
		header := strings.TrimSpace(m)
		desc := fmt.Sprintf("PEM private key header: %s [material redacted]", header)
		privKeyEvidence = append(privKeyEvidence, model.Evidence{
			Type:        model.EvidenceCredential,
			Description: desc,
			Source:      page.URL,
		})
	}

	privKeyEvidence = dedupeEvidence(privKeyEvidence)
	if len(privKeyEvidence) > 0 {
		if len(privKeyEvidence) > 10 {
			privKeyEvidence = privKeyEvidence[:10]
		}
		findings = append(findings, model.Finding{
			ID:             "CRED-002",
			Title:          "Private key header disclosed",
			Severity:       model.SeverityCritical,
			Confidence:     0.99,
			Target:         target.Onion,
			Analyzer:       a.Name(),
			Evidence:       privKeyEvidence,
			Explanation:    "A PEM-encoded private key header was found in page content. If an operator's private key (SSH, TLS, or onion service hidden service key) is exposed, the security, integrity, and anonymity of the service or host is fundamentally compromised.",
			Recommendation: "Treat the private key as completely compromised: rotate, regenerate, and revoke associated certificates or access keys immediately, and prevent server-side private key files from being served.",
			CreatedAt:      now,
		})
	}

	return findings, nil
}

// redactSecret redacts sensitive strings, keeping only prefix and suffix if long enough.
func redactSecret(secret string) string {
	trimmed := strings.TrimSpace(secret)
	if len(trimmed) <= 8 {
		return "[REDACTED]"
	}
	prefix := trimmed[:4]
	suffix := trimmed[len(trimmed)-4:]
	return fmt.Sprintf("%s...%s (len:%d)", prefix, suffix, len(trimmed))
}

func dedupeEvidence(in []model.Evidence) []model.Evidence {
	seen := make(map[string]bool)
	var out []model.Evidence
	for _, ev := range in {
		key := fmt.Sprintf("%s|%s|%s", ev.Type, ev.Description, ev.Source)
		if !seen[key] {
			seen[key] = true
			out = append(out, ev)
		}
	}
	return out
}
