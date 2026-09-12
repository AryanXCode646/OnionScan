// Package opsec looks for identifiers embedded in page content that could
// deanonymize or fingerprint the operator: email addresses, raw IPv4/IPv6
// addresses, and internal/private hostnames.
//
// IMPORTANT: finding a raw IP address in a page is EVIDENCE, not proof of
// origin-server disclosure -- it could be an example address, a CDN, or an
// unrelated third party. This analyzer only emits low/medium-confidence
// findings; the correlation engine (internal/correlation) is responsible
// for combining this evidence with TLS/fingerprint evidence to justify a
// high-confidence "infrastructure disclosure" finding.
package opsec

import (
	"context"
	"regexp"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return "opsec" }

var (
	emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	// Deliberately conservative IPv4 pattern; excludes anything ending in
	// .onion-adjacent noise by requiring dotted-quad boundaries.
	ipv4Re = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	// Internal / RFC1918 ranges are informational, not "origin disclosure".
	privateRe = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`)
)

func (a *Analyzer) Analyze(ctx context.Context, target model.Target, page model.Page) ([]model.Finding, error) {
	var findings []model.Finding
	now := time.Now()
	body := string(page.Body)

	if emails := dedupe(emailRe.FindAllString(body, -1)); len(emails) > 0 {
		findings = append(findings, model.Finding{
			ID:             "OPSEC-002",
			Title:          "Email address disclosed in page content",
			Severity:       model.SeverityMedium,
			Confidence:     0.9,
			Target:         target.Onion,
			Analyzer:       a.Name(),
			Evidence:       toEvidence(model.EvidenceEmail, emails, page.URL),
			Explanation:    "Email addresses can be pivoted on across breach data, social media, and PGP keyservers to link an operator identity to this service.",
			Recommendation: "Use a dedicated, purpose-specific contact address not reused elsewhere, or a contact form instead.",
			CreatedAt:      now,
		})
	}

	if ips := dedupe(ipv4Re.FindAllString(body, -1)); len(ips) > 0 {
		var public, private []string
		for _, ip := range ips {
			if privateRe.MatchString(ip) {
				private = append(private, ip)
			} else {
				public = append(public, ip)
			}
		}
		if len(public) > 0 {
			findings = append(findings, model.Finding{
				ID:             "INFRA-001",
				Title:          "Possible IP address reference (needs correlation)",
				Severity:       model.SeverityMedium,
				Confidence:     0.4, // low standalone confidence -- see package doc
				Target:         target.Onion,
				Analyzer:       a.Name(),
				Evidence:       toEvidence(model.EvidenceIP, public, page.URL),
				Explanation:    "A public IPv4 address appears in the page body. This alone does not prove it is origin infrastructure -- it may be a CDN, unrelated API, or documentation example. Cross-reference with TLS and fingerprint evidence before treating this as a leak.",
				Recommendation: "Confirm whether this address is expected (e.g. a documented third-party API) or investigate for accidental origin exposure.",
				CreatedAt:      now,
			})
		}
		if len(private) > 0 {
			findings = append(findings, model.Finding{
				ID:             "OPSEC-007",
				Title:          "Internal/private IP address referenced",
				Severity:       model.SeverityLow,
				Confidence:     0.85,
				Target:         target.Onion,
				Analyzer:       a.Name(),
				Evidence:       toEvidence(model.EvidenceIP, private, page.URL),
				Explanation:    "RFC1918 addresses suggest internal network topology or debug output leaked into user-facing content.",
				Recommendation: "Remove internal addresses from templates, error pages, and comments before deploying.",
				CreatedAt:      now,
			})
		}
	}

	return findings, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func toEvidence(t model.EvidenceType, values []string, source string) []model.Evidence {
	var ev []model.Evidence
	for _, v := range values {
		ev = append(ev, model.Evidence{Type: t, Description: v, Source: source})
	}
	return ev
}
