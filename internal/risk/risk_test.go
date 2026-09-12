package risk

import (
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestScore_Empty(t *testing.T) {
	if got := Score(nil); got != 0 {
		t.Errorf("Score(nil) = %d; want 0", got)
	}
	if got := Score([]model.Finding{}); got != 0 {
		t.Errorf("Score([]) = %d; want 0", got)
	}
}

func TestScore_SingleFinding(t *testing.T) {
	findings := []model.Finding{
		{
			ID:         "OPSEC-005",
			Title:      "Server disclosure",
			Severity:   model.SeverityLow, // weight 5
			Confidence: 0.8,
			Target:     "test.onion",
		},
	}
	// 5 * 0.8 = 4
	if got := Score(findings); got != 4 {
		t.Errorf("Score = %d; want 4", got)
	}
}

func TestScore_RepeatedFindingsDoNotInflate(t *testing.T) {
	// Issue #66: If 20 crawled pages all trigger OPSEC-005 (Low, weight 5, confidence 0.95),
	// without deduplication 20 * 5 * 0.95 = 95.
	// With deduplication, score must be int(5 * 0.95) = 4.
	var repeated []model.Finding
	for i := 0; i < 20; i++ {
		repeated = append(repeated, model.Finding{
			ID:         "OPSEC-005",
			Title:      "Server software/version disclosure",
			Severity:   model.SeverityLow,
			Confidence: 0.95,
			Target:     "target.onion",
			Evidence: []model.Evidence{
				{
					Type:        model.EvidenceHTTPHeader,
					Description: "Server: Apache/2.4.41",
					Source:      "http://target.onion/page" + string(rune('0'+i)),
				},
			},
		})
	}

	score := Score(repeated)
	if score != 4 {
		t.Fatalf("Score(repeated 20x) = %d; want 4 (un-inflated)", score)
	}
}

func TestScore_DistinctFindingsAccumulate(t *testing.T) {
	findings := []model.Finding{
		{
			ID:         "INFO-001",
			Title:      "Info finding",
			Severity:   model.SeverityInfo, // weight 0
			Confidence: 1.0,
			Target:     "test.onion",
		},
		{
			ID:         "OPSEC-001",
			Title:      "Low finding",
			Severity:   model.SeverityLow, // weight 5
			Confidence: 1.0,
			Target:     "test.onion",
		},
		{
			ID:         "OPSEC-002",
			Title:      "Medium finding",
			Severity:   model.SeverityMedium, // weight 15
			Confidence: 1.0,
			Target:     "test.onion",
		},
		{
			ID:         "INFRA-001",
			Title:      "High finding",
			Severity:   model.SeverityHigh, // weight 30
			Confidence: 1.0,
			Target:     "test.onion",
		},
	}
	// 0 + 5 + 15 + 30 = 50
	if got := Score(findings); got != 50 {
		t.Errorf("Score = %d; want 50", got)
	}
}

func TestScore_CapAt100(t *testing.T) {
	findings := []model.Finding{
		{
			ID:         "CRIT-001",
			Title:      "Critical 1",
			Severity:   model.SeverityCritical, // weight 50
			Confidence: 1.0,
			Target:     "test.onion",
		},
		{
			ID:         "CRIT-002",
			Title:      "Critical 2",
			Severity:   model.SeverityCritical, // weight 50
			Confidence: 1.0,
			Target:     "test.onion",
		},
		{
			ID:         "CRIT-003",
			Title:      "Critical 3",
			Severity:   model.SeverityCritical, // weight 50
			Confidence: 1.0,
			Target:     "test.onion",
		},
	}
	// 50 + 50 + 50 = 150 -> bounded at 100
	if got := Score(findings); got != 100 {
		t.Errorf("Score = %d; want 100", got)
	}
}

func TestDeduplicateFindings_Empty(t *testing.T) {
	if got := DeduplicateFindings(nil); got != nil {
		t.Errorf("DeduplicateFindings(nil) = %v; want nil", got)
	}
	if got := DeduplicateFindings([]model.Finding{}); got != nil {
		t.Errorf("DeduplicateFindings([]) = %v; want nil", got)
	}
}

func TestDeduplicateFindings_MergesEvidenceAndPicksMaxConfidenceAndSeverity(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 1, 12, 5, 0, 0, time.UTC)

	findings := []model.Finding{
		{
			ID:             "OPSEC-005",
			Title:          "Server software/version disclosure",
			Severity:       model.SeverityLow,
			Confidence:     0.70,
			Target:         "example.onion",
			Analyzer:       "headers",
			Explanation:    "Server header exposed",
			Recommendation: "Remove Server header",
			CreatedAt:      t2,
			Evidence: []model.Evidence{
				{Type: model.EvidenceHTTPHeader, Description: "Server: Apache", Source: "http://example.onion/"},
				{Type: model.EvidenceHTTPHeader, Description: "Server: Apache", Source: "http://example.onion/"}, // duplicate in same finding
			},
		},
		{
			ID:             "OPSEC-005",
			Title:          "Server software/version disclosure",
			Severity:       model.SeverityMedium, // escalated severity
			Confidence:     0.95,                 // higher confidence
			Target:         "example.onion",
			Analyzer:       "headers",
			Explanation:    "Server header exposed",
			Recommendation: "Remove Server header",
			CreatedAt:      t1, // earlier timestamp
			Evidence: []model.Evidence{
				{Type: model.EvidenceHTTPHeader, Description: "Server: Apache", Source: "http://example.onion/"},      // duplicate from first finding
				{Type: model.EvidenceHTTPHeader, Description: "Server: Apache", Source: "http://example.onion/page2"}, // new evidence
			},
		},
	}

	deduped := DeduplicateFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(deduped))
	}

	f := deduped[0]
	if f.Confidence != 0.95 {
		t.Errorf("expected max confidence 0.95, got %f", f.Confidence)
	}
	if f.Severity != model.SeverityMedium {
		t.Errorf("expected max severity %s, got %s", model.SeverityMedium, f.Severity)
	}
	if !f.CreatedAt.Equal(t1) {
		t.Errorf("expected earliest CreatedAt %v, got %v", t1, f.CreatedAt)
	}
	if len(f.Evidence) != 2 {
		t.Fatalf("expected 2 unique evidence items, got %d: %+v", len(f.Evidence), f.Evidence)
	}

	sources := map[string]bool{}
	for _, ev := range f.Evidence {
		sources[ev.Source] = true
	}
	if !sources["http://example.onion/"] || !sources["http://example.onion/page2"] {
		t.Errorf("expected evidence from both pages, got %+v", sources)
	}
}

func TestDeduplicateFindings_PreservesOrderAndDistinguishesFindings(t *testing.T) {
	findings := []model.Finding{
		{
			ID:         "RULE-001",
			Title:      "First Finding",
			Target:     "site.onion",
			Confidence: 0.5,
		},
		{
			ID:         "RULE-002",
			Title:      "Second Finding",
			Target:     "site.onion",
			Confidence: 0.6,
		},
		{
			ID:         "RULE-001",
			Title:      "First Finding",
			Target:     "site.onion",
			Confidence: 0.8,
		},
		{
			ID:         "RULE-001",
			Title:      "Different Title Sharing Same Rule ID",
			Target:     "site.onion",
			Confidence: 0.9,
		},
		{
			ID:         "RULE-001",
			Title:      "First Finding",
			Target:     "different.onion", // different target
			Confidence: 0.7,
		},
	}

	deduped := DeduplicateFindings(findings)
	if len(deduped) != 4 {
		t.Fatalf("expected 4 deduplicated findings, got %d", len(deduped))
	}

	if deduped[0].ID != "RULE-001" || deduped[0].Title != "First Finding" || deduped[0].Target != "site.onion" {
		t.Errorf("unexpected first finding: %+v", deduped[0])
	}
	if deduped[0].Confidence != 0.8 {
		t.Errorf("expected confidence 0.8 for first finding, got %f", deduped[0].Confidence)
	}

	if deduped[1].ID != "RULE-002" || deduped[1].Title != "Second Finding" {
		t.Errorf("unexpected second finding: %+v", deduped[1])
	}

	if deduped[2].ID != "RULE-001" || deduped[2].Title != "Different Title Sharing Same Rule ID" {
		t.Errorf("unexpected third finding: %+v", deduped[2])
	}

	if deduped[3].ID != "RULE-001" || deduped[3].Target != "different.onion" {
		t.Errorf("unexpected fourth finding: %+v", deduped[3])
	}
}

// makeF is a concise helper for constructing a Finding in table tests.
func makeF(id string, sev model.Severity, conf float64) model.Finding {
	return model.Finding{
		ID:         id,
		Title:      id,
		Severity:   sev,
		Confidence: conf,
		Target:     "test.onion",
		Analyzer:   "test",
		CreatedAt:  time.Now(),
	}
}

func TestScore_ConfidenceWeighting(t *testing.T) {
	findings := []model.Finding{
		makeF("M-001", model.SeverityMedium, 0.8),
	}
	// 15 * 0.8 = 12
	got := Score(findings)
	if got != 12 {
		t.Errorf("Score(Medium@0.8) = %d, want 12", got)
	}
}

func TestScore_UnknownSeverityIgnored(t *testing.T) {
	unknown := model.Finding{
		ID:         "U-001",
		Severity:   model.Severity("BOGUS"),
		Confidence: 1.0,
		Target:     "test.onion",
		Analyzer:   "test",
	}
	got := Score([]model.Finding{unknown})
	if got != 0 {
		t.Errorf("Score([unknown severity]) = %d, want 0 (ignored)", got)
	}

	mixed := []model.Finding{
		unknown,
		makeF("L-001", model.SeverityLow, 1.0),
	}
	got = Score(mixed)
	if got != 5 {
		t.Errorf("Score([unknown + LOW]) = %d, want 5", got)
	}
}

func TestScore_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		findings []model.Finding
		want     int
	}{
		{
			name:     "one INFO",
			findings: []model.Finding{makeF("I", model.SeverityInfo, 1.0)},
			want:     0,
		},
		{
			name:     "one LOW",
			findings: []model.Finding{makeF("L", model.SeverityLow, 1.0)},
			want:     5,
		},
		{
			name:     "one MEDIUM",
			findings: []model.Finding{makeF("M", model.SeverityMedium, 1.0)},
			want:     15,
		},
		{
			name:     "one HIGH",
			findings: []model.Finding{makeF("H", model.SeverityHigh, 1.0)},
			want:     30,
		},
		{
			name:     "one CRITICAL",
			findings: []model.Finding{makeF("C", model.SeverityCritical, 1.0)},
			want:     50,
		},
		{
			name:     "LOW half-confidence",
			findings: []model.Finding{makeF("L", model.SeverityLow, 0.5)},
			want:     2,
		},
		{
			name: "exceed cap distinct",
			findings: []model.Finding{
				makeF("C1", model.SeverityCritical, 1.0),
				makeF("C2", model.SeverityCritical, 1.0),
				makeF("C3", model.SeverityCritical, 1.0),
			},
			want: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Score(tt.findings)
			if got != tt.want {
				t.Errorf("Score() = %d, want %d", got, tt.want)
			}
		})
	}
}
