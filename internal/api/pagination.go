package api

import (
	"fmt"
	"net/http"
	"strconv"
)

const (
	defaultPageLimit = 50
	maxPageLimit     = 500
)

// pageParams holds validated pagination parameters.
type pageParams struct {
	Limit  int
	Offset int
}

// parsePagination reads ?limit= and ?offset= from the request, validates them,
// and returns a populated pageParams or writes an HTTP 400 response and returns false.
//
// Rules:
//   - missing limit  → default 50
//   - missing offset → default 0
//   - limit  > 500   → clamped to 500 (no error, no surprise)
//   - limit  <= 0    → 400 INVALID_PARAMETER
//   - offset < 0     → 400 INVALID_PARAMETER
//   - non-numeric    → 400 INVALID_PARAMETER
func parsePagination(w http.ResponseWriter, r *http.Request) (pageParams, bool) {
	p := pageParams{
		Limit:  defaultPageLimit,
		Offset: 0,
	}

	if limStr := r.URL.Query().Get("limit"); limStr != "" {
		val, err := strconv.Atoi(limStr)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "INVALID_PARAMETER",
				fmt.Sprintf("invalid limit: %q is not a valid integer", limStr))
			return pageParams{}, false
		}
		if val <= 0 {
			writeJSONError(w, http.StatusBadRequest, "INVALID_PARAMETER",
				"invalid limit: must be a positive integer")
			return pageParams{}, false
		}
		if val > maxPageLimit {
			val = maxPageLimit
		}
		p.Limit = val
	}

	if offStr := r.URL.Query().Get("offset"); offStr != "" {
		val, err := strconv.Atoi(offStr)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "INVALID_PARAMETER",
				fmt.Sprintf("invalid offset: %q is not a valid integer", offStr))
			return pageParams{}, false
		}
		if val < 0 {
			writeJSONError(w, http.StatusBadRequest, "INVALID_PARAMETER",
				"invalid offset: must be zero or positive")
			return pageParams{}, false
		}
		p.Offset = val
	}

	return p, true
}
