// Package risk turns a list of Findings into a single 0-100 score so users
// get a one-glance sense of exposure. The weighting here is a deliberately
// simple starting point -- see issue "Tune risk scoring weights against
// real-world scans" before relying on this for anything beyond MVP demos.
package risk

import "github.com/AryanXCode646/OnionScan/internal/model"

var severityWeight = map[model.Severity]float64{
	model.SeverityInfo:     0,
	model.SeverityLow:      5,
	model.SeverityMedium:   15,
	model.SeverityHigh:     30,
	model.SeverityCritical: 50,
}

// Score computes a bounded 0-100 risk score from a set of findings,
// weighting each by severity and confidence.
func Score(findings []model.Finding) int {
	total := 0.0
	for _, f := range findings {
		w, ok := severityWeight[f.Severity]
		if !ok {
			continue
		}
		total += w * f.Confidence
	}
	if total > 100 {
		total = 100
	}
	return int(total)
}
