// Package headers implements OPSEC-001 / OPSEC-005 style checks against
// HTTP response headers: missing security headers and server/software
// version disclosure.
package headers

import (
	"context"
	"strings"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return "headers" }

var securityHeaders = []string{
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
}

func (a *Analyzer) Analyze(ctx context.Context, target model.Target, page model.Page) ([]model.Finding, error) {
	var findings []model.Finding
	now := time.Now()

	// Server / X-Powered-By disclosure.
	for _, h := range []string{"Server", "X-Powered-By"} {
		if v, ok := page.Headers[h]; ok && strings.TrimSpace(v) != "" {
			findings = append(findings, model.Finding{
				ID:         "OPSEC-005",
				Title:      "Server software/version disclosure",
				Severity:   model.SeverityLow,
				Confidence: 0.95,
				Target:     target.Onion,
				Analyzer:   a.Name(),
				Evidence: []model.Evidence{{
					Type:        model.EvidenceHTTPHeader,
					Description: h + ": " + v,
					Source:      page.URL,
				}},
				Explanation:    "The response advertises specific server software and/or version, which narrows the search space for known vulnerabilities and can help correlate this onion service with a clearnet host running the same stack.",
				Recommendation: "Suppress or genericize the " + h + " header at the reverse proxy.",
				CreatedAt:      now,
			})
		}
	}

	// Missing security headers (informational aggregate).
	var missing []string
	for _, h := range securityHeaders {
		if _, ok := page.Headers[h]; !ok {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		findings = append(findings, model.Finding{
			ID:         "OPSEC-006",
			Title:      "Missing recommended security headers",
			Severity:   model.SeverityInfo,
			Confidence: 1.0,
			Target:     target.Onion,
			Analyzer:   a.Name(),
			Evidence: []model.Evidence{{
				Type:        model.EvidenceHTTPHeader,
				Description: "Missing: " + strings.Join(missing, ", "),
				Source:      page.URL,
			}},
			Explanation:    "These headers reduce the impact of XSS/clickjacking and limit accidental leakage of referrer data to embedded external resources.",
			Recommendation: "Add the missing headers at the application or reverse-proxy layer.",
			CreatedAt:      now,
		})
	}

	return findings, nil
}
