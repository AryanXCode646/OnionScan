package headers

import (
	"context"
	"testing"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestAnalyze_ServerDisclosure(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	page := model.Page{
		URL: "http://test.onion/",
		Headers: map[string]string{
			"Server": "nginx/1.18.0",
		},
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.ID == "OPSEC-005" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected OPSEC-005 finding for Server header disclosure, got %+v", findings)
	}
}

func TestAnalyze_NoDisclosure(t *testing.T) {
	a := New()
	target := model.Target{Onion: "test.onion"}
	page := model.Page{
		URL: "http://test.onion/",
		Headers: map[string]string{
			"Content-Security-Policy": "default-src 'self'",
			"X-Frame-Options":         "DENY",
			"X-Content-Type-Options":  "nosniff",
			"Referrer-Policy":         "no-referrer",
		},
	}

	findings, err := a.Analyze(context.Background(), target, page)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.ID == "OPSEC-005" || f.ID == "OPSEC-006" {
			t.Errorf("did not expect %s finding when headers are clean and complete, got %+v", f.ID, f)
		}
	}
}
