package model

import "time"

// Severity levels for a Finding.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// EvidenceType categorizes a single piece of supporting evidence.
type EvidenceType string

const (
	EvidenceIP          EvidenceType = "ip"
	EvidenceHostname    EvidenceType = "hostname"
	EvidenceTLS         EvidenceType = "tls"
	EvidenceHTTPHeader  EvidenceType = "http_header"
	EvidenceFingerprint EvidenceType = "fingerprint"
	EvidenceMetadata    EvidenceType = "metadata"
	EvidenceEmail       EvidenceType = "email"
	EvidenceExternalRes EvidenceType = "external_resource"
	EvidenceCredential  EvidenceType = "credential"
)

// Evidence is one observed fact that supports a Finding. Findings should
// never be emitted from a single regex match alone -- prefer accumulating
// Evidence and letting the risk/correlation layer decide confidence.
type Evidence struct {
	Type        EvidenceType `json:"type"`
	Description string       `json:"description"`
	Source      string       `json:"source"` // e.g. URL or analyzer name the evidence came from
}

// Finding is a single reportable security/OPSEC observation about a Target.
type Finding struct {
	ID             string     `json:"id"` // stable rule id, e.g. OPSEC-003
	Title          string     `json:"title"`
	Severity       Severity   `json:"severity"`
	Confidence     float64    `json:"confidence"` // 0.0 - 1.0
	Target         string     `json:"target"`     // onion address
	Analyzer       string     `json:"analyzer"`   // which analyzer produced this
	Evidence       []Evidence `json:"evidence"`
	Explanation    string     `json:"explanation"`
	Recommendation string     `json:"recommendation"`
	CreatedAt      time.Time  `json:"created_at"`
}

// ScanResult is the full output of a single scan run against one Target.
type ScanResult struct {
	Target    Target    `json:"target"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	PagesSeen int       `json:"pages_seen"`
	Findings  []Finding `json:"findings"`
	RiskScore int       `json:"risk_score"` // 0-100, higher = worse
}
