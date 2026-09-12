// Package analyzer defines the plugin interface that every detection module
// implements. Analyzers should be small, single-purpose, and emit Evidence
// rather than jumping straight to a high-confidence Finding wherever
// possible -- correlation across analyzers is what turns raw evidence into
// a trustworthy finding (see internal/correlation).
package analyzer

import (
	"context"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

// Analyzer inspects one fetched Page (or the accumulated set of pages for a
// Target, depending on the analyzer) and returns zero or more Findings.
type Analyzer interface {
	// Name returns a short, stable, lowercase identifier, e.g. "headers".
	Name() string

	// Analyze runs the detection logic against a single page. Analyzers
	// must not mutate page.Body and must respect ctx cancellation/timeouts.
	Analyze(ctx context.Context, target model.Target, page model.Page) ([]model.Finding, error)
}

// Registry holds every analyzer that a scan run should execute.
type Registry struct {
	analyzers []Analyzer
}

// NewRegistry builds an empty analyzer registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds an analyzer to the registry. Order of registration is the
// order analyzers run in.
func (r *Registry) Register(a Analyzer) {
	r.analyzers = append(r.analyzers, a)
}

// All returns every registered analyzer.
func (r *Registry) All() []Analyzer {
	return r.analyzers
}
