package report

import (
	"encoding/json"
	"io"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

// WriteJSON serializes a ScanResult as pretty-printed JSON.
func WriteJSON(w io.Writer, result model.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
