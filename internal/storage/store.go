// Package storage persists scan history so `onionsec monitor` can diff one
// run against the last. The MVP uses one JSON file per scan on disk to
// avoid a cgo/SQLite dependency; see issue "Phase 4: migrate storage to
// SQLite" for the upgrade path once monitoring needs real querying
// (change history, comparisons across many targets, etc).
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

// Store reads/writes scan results under a base directory, one subfolder
// per target (sanitized) and one JSON file per scan timestamp.
type Store struct {
	BaseDir string
}

func New(baseDir string) *Store {
	return &Store{BaseDir: baseDir}
}

func (s *Store) targetDir(onion string) string {
	safe := strings.NewReplacer("/", "_", ":", "_").Replace(onion)
	return filepath.Join(s.BaseDir, safe)
}

// Save writes a scan result and returns the file path it was written to.
func (s *Store) Save(result model.ScanResult) (string, error) {
	dir := s.targetDir(result.Target.Onion)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create scan dir: %w", err)
	}
	name := result.EndedAt.UTC().Format("20060102T150405Z") + ".json"
	path := filepath.Join(dir, name)

	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create scan file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return "", fmt.Errorf("write scan file: %w", err)
	}
	return path, nil
}

// History returns every past scan for a target, oldest first.
func (s *Store) History(onion string) ([]model.ScanResult, error) {
	dir := s.targetDir(onion)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // filenames are timestamp-prefixed, so lexical == chronological

	var results []model.ScanResult
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		var r model.ScanResult
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, nil
}

// Latest returns the most recent scan for a target, or ok=false if none exist.
func (s *Store) Latest(onion string) (result model.ScanResult, ok bool, err error) {
	hist, err := s.History(onion)
	if err != nil || len(hist) == 0 {
		return model.ScanResult{}, false, err
	}
	return hist[len(hist)-1], true, nil
}
