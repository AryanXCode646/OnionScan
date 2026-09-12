// Package correlation is the project's core differentiator (see
// docs/ROADMAP.md Phase 3): turning independent pieces of Evidence into a
// small number of high-confidence relationship Findings, instead of
// dumping every raw regex hit on the user.
//
// The MVP implementation here only does same-scan aggregation (e.g. "this
// IP evidence was seen alongside this fingerprint evidence"). Cross-scan
// and cross-target correlation (the real "evidence graph" from the design
// doc) is intentionally left as a tracked follow-up issue --
// "Phase 3: cross-target evidence graph" -- because it needs a persistent
// store (see internal/storage) with more than one scan in it.
package correlation

import (
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

// Correlate inspects the findings from a single scan and, where multiple
// independent evidence types point at the same underlying fact, emits an
// additional higher-confidence Finding summarizing the relationship.
//
// TODO: this is intentionally simple for the MVP. See issue
// "Phase 3: implement real evidence-graph correlation" for the design of
// a proper weighted-confidence model instead of the fixed bump used here.
func Correlate(target model.Target, findings []model.Finding) []model.Finding {
	hasIP := false
	hasFingerprint := false
	var ipEvidence []model.Evidence

	for _, f := range findings {
		for _, e := range f.Evidence {
			switch e.Type {
			case model.EvidenceIP:
				hasIP = true
				ipEvidence = append(ipEvidence, e)
			case model.EvidenceFingerprint:
				hasFingerprint = true
			}
		}
	}

	if hasIP && hasFingerprint {
		return append(findings, model.Finding{
			ID:             "INFRA-002",
			Title:          "Possible origin infrastructure disclosure (correlated)",
			Severity:       model.SeverityHigh,
			Confidence:     0.7,
			Target:         target.Onion,
			Analyzer:       "correlation",
			Evidence:       ipEvidence,
			Explanation:    "A referenced IP address co-occurred with a recorded response fingerprint in the same scan. This raises confidence above a standalone IP mention, but should still be manually verified before treating it as a confirmed leak.",
			Recommendation: "Manually verify whether the referenced address is reachable and serves the same content as this onion service.",
			CreatedAt:      time.Now(),
		})
	}

	return findings
}
