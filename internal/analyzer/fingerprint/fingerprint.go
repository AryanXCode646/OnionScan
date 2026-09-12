// Package fingerprint builds a lightweight signature of a page/response so
// the correlation engine can later ask "have we seen this exact stack
// elsewhere?" (see docs/ROADMAP.md Phase 3). This is intentionally a stub
// for the MVP: it computes a stable hash of a few structural signals rather
// than doing real cross-target correlation yet. Tracked in issue
// "Phase 3: implement fingerprint similarity scoring".
package fingerprint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return "fingerprint" }

func (a *Analyzer) Analyze(ctx context.Context, target model.Target, page model.Page) ([]model.Finding, error) {
	sig := signature(page)

	return []model.Finding{{
		ID:         "FP-001",
		Title:      "Response fingerprint recorded",
		Severity:   model.SeverityInfo,
		Confidence: 1.0,
		Target:     target.Onion,
		Analyzer:   a.Name(),
		Evidence: []model.Evidence{{
			Type:        model.EvidenceFingerprint,
			Description: sig,
			Source:      page.URL,
		}},
		Explanation:    "Recorded for use by the correlation engine to detect infrastructure reuse across scans/targets and to detect drift over time via `onionsec monitor`.",
		Recommendation: "No action needed; informational.",
		CreatedAt:      time.Now(),
	}}, nil
}

// signature hashes a stable, ordered subset of headers plus status code.
// TODO(Phase 3): incorporate response timing buckets, TLS cert fields, and
// body structure (e.g. DOM tag histogram) once the correlation engine can
// consume richer evidence.
func signature(page model.Page) string {
	var keys []string
	for k := range page.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(page.Headers[k])
		b.WriteByte(';')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}
