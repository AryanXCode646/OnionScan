package model

import "time"

// Target is a single authorized onion service being scanned.
type Target struct {
	Onion     string    `json:"onion"`           // e.g. exampleabc...xyz.onion
	Label     string    `json:"label,omitempty"` // optional human-friendly name
	CreatedAt time.Time `json:"created_at"`
}

// Page is a single fetched resource belonging to a Target.
type Page struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"-"` // never serialized directly; keep out of reports
	FetchedAt  time.Time         `json:"fetched_at"`
}
