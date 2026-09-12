package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

var severityOrder = map[model.Severity]int{
	model.SeverityCritical: 0,
	model.SeverityHigh:     1,
	model.SeverityMedium:   2,
	model.SeverityLow:      3,
	model.SeverityInfo:     4,
}

// WriteMarkdown renders a human-readable report, most severe findings first.
func WriteMarkdown(w io.Writer, result model.ScanResult) error {
	fmt.Fprintf(w, "# OnionSec report: %s\n\n", result.Target.Onion)
	fmt.Fprintf(w, "- Scanned: %s\n", result.StartedAt.Format("2006-01-02 15:04 MST"))
	fmt.Fprintf(w, "- Pages seen: %d\n", result.PagesSeen)
	fmt.Fprintf(w, "- Risk score: **%d / 100**\n\n", result.RiskScore)

	findings := append([]model.Finding(nil), result.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
	})

	if len(findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return nil
	}

	for _, f := range findings {
		fmt.Fprintf(w, "## [%s] %s (%s)\n\n", f.Severity, f.Title, f.ID)
		fmt.Fprintf(w, "Confidence: %.0f%%\n\n", f.Confidence*100)
		fmt.Fprintf(w, "%s\n\n", f.Explanation)
		if len(f.Evidence) > 0 {
			fmt.Fprintln(w, "Evidence:")
			for _, e := range f.Evidence {
				fmt.Fprintf(w, "- `%s`: %s (source: %s)\n", e.Type, e.Description, e.Source)
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "**Recommendation:** %s\n\n", f.Recommendation)
	}
	return nil
}
