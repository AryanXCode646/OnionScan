package storage

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

func TestStore_SaveAndLatestRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	store, err := New(tempDir)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer store.Close()

	onion := "testtarget.onion"
	now := time.Date(2026, 9, 12, 8, 30, 0, 0, time.UTC)
	expected := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: now.Add(-1 * time.Minute),
		EndedAt:   now,
		RiskScore: 42,
		Findings: []model.Finding{
			{
				ID:         "OPSEC-002",
				Title:      "Email address disclosed",
				Severity:   model.SeverityMedium,
				Confidence: 0.9,
				Target:     onion,
				Analyzer:   "opsec",
				CreatedAt:  now,
			},
		},
	}

	path, err := store.Save(expected)
	if err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}
	if path == "" {
		t.Errorf("expected non-empty path from Save")
	}

	latest, ok, err := store.Latest(onion)
	if err != nil {
		t.Fatalf("unexpected latest error: %v", err)
	}
	if !ok {
		t.Fatalf("expected latest scan to be found")
	}

	if latest.Target.Onion != expected.Target.Onion {
		t.Errorf("expected target %s, got %s", expected.Target.Onion, latest.Target.Onion)
	}
	if latest.RiskScore != expected.RiskScore {
		t.Errorf("expected risk score %d, got %d", expected.RiskScore, latest.RiskScore)
	}
	if len(latest.Findings) != len(expected.Findings) {
		t.Fatalf("expected %d findings, got %d", len(expected.Findings), len(latest.Findings))
	}
	if latest.Findings[0].ID != expected.Findings[0].ID {
		t.Errorf("expected finding ID %s, got %s", expected.Findings[0].ID, latest.Findings[0].ID)
	}
	if !latest.EndedAt.Equal(expected.EndedAt) {
		t.Errorf("expected endedAt %v, got %v", expected.EndedAt, latest.EndedAt)
	}
}

func TestStore_HistoryOrdering(t *testing.T) {
	tempDir := t.TempDir()
	store, err := New(tempDir)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer store.Close()
	onion := "timeline.onion"

	t1 := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	scans := []model.ScanResult{
		{Target: model.Target{Onion: onion}, EndedAt: t2, RiskScore: 20},
		{Target: model.Target{Onion: onion}, EndedAt: t1, RiskScore: 10},
		{Target: model.Target{Onion: onion}, EndedAt: t3, RiskScore: 30},
	}

	for _, s := range scans {
		if _, err := store.Save(s); err != nil {
			t.Fatalf("failed to save scan with endedAt %v: %v", s.EndedAt, err)
		}
	}

	history, err := store.History(onion)
	if err != nil {
		t.Fatalf("unexpected history error: %v", err)
	}

	if len(history) != 3 {
		t.Fatalf("expected 3 history entries, got %d", len(history))
	}

	// History must be ordered oldest first: t1, t2, t3
	if !history[0].EndedAt.Equal(t1) || history[0].RiskScore != 10 {
		t.Errorf("expected first scan to be t1 (score 10), got %+v", history[0])
	}
	if !history[1].EndedAt.Equal(t2) || history[1].RiskScore != 20 {
		t.Errorf("expected second scan to be t2 (score 20), got %+v", history[1])
	}
	if !history[2].EndedAt.Equal(t3) || history[2].RiskScore != 30 {
		t.Errorf("expected third scan to be t3 (score 30), got %+v", history[2])
	}

	latest, ok, err := store.Latest(onion)
	if err != nil {
		t.Fatalf("unexpected latest error: %v", err)
	}
	if !ok {
		t.Fatalf("expected latest scan to be found")
	}
	if !latest.EndedAt.Equal(t3) || latest.RiskScore != 30 {
		t.Errorf("expected latest scan to be t3 (score 30), got %+v", latest)
	}
}

func TestStore_NonExistentTarget(t *testing.T) {
	tempDir := t.TempDir()
	store, err := New(tempDir)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer store.Close()

	latest, ok, err := store.Latest("nonexistent.onion")
	if err != nil {
		t.Fatalf("unexpected error on missing target: %v", err)
	}
	if ok {
		t.Errorf("expected ok=false for missing target, got true with %+v", latest)
	}

	history, err := store.History("nonexistent.onion")
	if err != nil {
		t.Fatalf("unexpected error on missing history: %v", err)
	}
	if len(history) != 0 {
		t.Errorf("expected empty history for missing target, got %d entries", len(history))
	}
}

func TestStore_EvidenceIndexingAndLookup(t *testing.T) {
	tempDir := t.TempDir()
	store, err := New(tempDir)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer store.Close()

	target1 := "alpha.onion"
	target2 := "beta.onion"
	sharedIP := "198.51.100.42"

	scan1 := model.ScanResult{
		Target:    model.Target{Onion: target1},
		StartedAt: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
		EndedAt:   time.Date(2026, 9, 12, 10, 1, 0, 0, time.UTC),
		Findings: []model.Finding{
			{
				ID:       "INFRA-001",
				Analyzer: "opsec",
				Evidence: []model.Evidence{
					{Type: model.EvidenceIP, Description: sharedIP, Source: "http://alpha.onion/about"},
					{Type: model.EvidenceEmail, Description: "admin@sharedcorp.com", Source: "http://alpha.onion/contact"},
					{Type: model.EvidenceCredential, Description: "secret_token_redacted", Source: "http://alpha.onion/config"},
				},
			},
		},
	}

	if _, err := store.Save(scan1); err != nil {
		t.Fatalf("failed to save scan1: %v", err)
	}

	scan2 := model.ScanResult{
		Target:    model.Target{Onion: target2},
		StartedAt: time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC),
		EndedAt:   time.Date(2026, 9, 12, 11, 1, 0, 0, time.UTC),
		Findings: []model.Finding{
			{
				ID:       "INFRA-001",
				Analyzer: "opsec",
				Evidence: []model.Evidence{
					{Type: model.EvidenceIP, Description: sharedIP, Source: "http://beta.onion/api"},
				},
			},
		},
	}

	if _, err := store.Save(scan2); err != nil {
		t.Fatalf("failed to save scan2: %v", err)
	}

	// 1. Query shared IP -> should return both alpha.onion and beta.onion
	links, err := store.FindCoOccurringTargets(model.EvidenceIP, sharedIP)
	if err != nil {
		t.Fatalf("FindCoOccurringTargets failed: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("expected 2 targets for shared IP, got %d", len(links))
	}

	// 2. Query email -> should only return alpha.onion
	emailLinks, err := store.FindCoOccurringTargets(model.EvidenceEmail, "ADMIN@SharedCorp.COM") // tests canonicalization
	if err != nil {
		t.Fatalf("FindCoOccurringTargets email failed: %v", err)
	}
	if len(emailLinks) != 1 || emailLinks[0].Onion != target1 {
		t.Fatalf("expected 1 target (alpha.onion) for email, got %+v", emailLinks)
	}

	// 3. Query credentials -> must be empty (safety rule)
	credLinks, err := store.FindCoOccurringTargets(model.EvidenceCredential, "secret_token_redacted")
	if err != nil {
		t.Fatalf("unexpected cred query error: %v", err)
	}
	if len(credLinks) != 0 {
		t.Fatalf("expected 0 targets for credentials (safety rule), got %d", len(credLinks))
	}

	// 4. Test Targets() listing
	targets, err := store.Targets()
	if err != nil {
		t.Fatalf("Targets() failed: %v", err)
	}
	if len(targets) != 2 || targets[0] != "alpha.onion" || targets[1] != "beta.onion" {
		t.Fatalf("expected [alpha.onion beta.onion], got %+v", targets)
	}
}

func TestFileStore_SaveAndRetrieve(t *testing.T) {
	tempDir := t.TempDir()
	fs := NewFileStore(tempDir)
	defer fs.Close()

	onion := "filestore.onion"
	res := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: time.Now().Add(-time.Minute),
		EndedAt:   time.Now(),
		RiskScore: 15,
	}

	path, err := fs.Save(res)
	if err != nil {
		t.Fatalf("FileStore.Save failed: %v", err)
	}
	if path == "" {
		t.Errorf("expected non-empty path from Save")
	}

	latest, ok, err := fs.Latest(onion)
	if err != nil || !ok {
		t.Fatalf("FileStore.Latest failed: %v, ok=%v", err, ok)
	}
	if latest.RiskScore != 15 {
		t.Errorf("expected risk score 15, got %d", latest.RiskScore)
	}
}

func TestSQLiteStore_InMemory(t *testing.T) {
	store, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite(:memory:) failed: %v", err)
	}
	defer store.Close()

	onion := "memory.onion"
	res := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: time.Now().Add(-time.Minute),
		EndedAt:   time.Now(),
		RiskScore: 88,
	}

	scanID, err := store.Save(res)
	if err != nil {
		t.Fatalf("Save in memory failed: %v", err)
	}
	if scanID == "" {
		t.Errorf("expected non-empty scanID")
	}

	latest, ok, err := store.Latest(onion)
	if err != nil || !ok {
		t.Fatalf("Latest in memory failed: %v, ok=%v", err, ok)
	}
	if latest.RiskScore != 88 {
		t.Errorf("expected risk score 88, got %d", latest.RiskScore)
	}
}

func TestStore_GetScan(t *testing.T) {
	tempDir := t.TempDir()
	sqliteStore, err := New(tempDir)
	if err != nil {
		t.Fatalf("New sqlite store failed: %v", err)
	}
	defer sqliteStore.Close()

	fileStore := NewFileStore(tempDir + "_file")
	defer fileStore.Close()

	onion := "getscan.onion"
	now := time.Date(2026, 9, 12, 12, 30, 0, 0, time.UTC)
	res := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: now.Add(-time.Minute),
		EndedAt:   now,
		RiskScore: 77,
	}

	for _, s := range []Store{sqliteStore, fileStore} {
		_, err := s.Save(res)
		if err != nil {
			t.Fatalf("Save failed: %v", err)
		}

		scanID := "20260912T123000Z"
		retrieved, ok, err := s.GetScan(onion, scanID)
		if err != nil {
			t.Fatalf("GetScan failed: %v", err)
		}
		if !ok {
			t.Fatalf("GetScan returned ok=false for existing scan")
		}
		if retrieved.RiskScore != 77 {
			t.Errorf("expected risk score 77, got %d", retrieved.RiskScore)
		}

		_, missingOk, err := s.GetScan(onion, "nonexistent-scan-id")
		if err != nil {
			t.Fatalf("GetScan error on missing scan: %v", err)
		}
		if missingOk {
			t.Errorf("expected missingOk=false for nonexistent scan")
		}
	}
}

func TestStore_ListAssets(t *testing.T) {
	tempDir := t.TempDir()
	sqliteStore, err := New(tempDir)
	if err != nil {
		t.Fatalf("New sqlite store failed: %v", err)
	}
	defer sqliteStore.Close()

	fileStore := NewFileStore(tempDir + "_file")
	defer fileStore.Close()

	now := time.Date(2026, 9, 12, 12, 30, 0, 0, time.UTC)
	res1 := model.ScanResult{
		Target:    model.Target{Onion: "target1.onion"},
		StartedAt: now.Add(-time.Minute),
		EndedAt:   now,
		Findings: []model.Finding{
			{
				ID: "OPSEC-001",
				Evidence: []model.Evidence{
					{Type: model.EvidenceIP, Description: "198.51.100.1"},
				},
			},
		},
	}
	res2 := model.ScanResult{
		Target:    model.Target{Onion: "target2.onion"},
		StartedAt: now.Add(-time.Minute),
		EndedAt:   now,
		Findings: []model.Finding{
			{
				ID: "OPSEC-001",
				Evidence: []model.Evidence{
					{Type: model.EvidenceIP, Description: "198.51.100.1"},
				},
			},
		},
	}

	for _, s := range []Store{sqliteStore, fileStore} {
		if err := s.IndexEvidence(res1); err != nil {
			t.Fatalf("IndexEvidence res1 failed: %v", err)
		}
		if err := s.IndexEvidence(res2); err != nil {
			t.Fatalf("IndexEvidence res2 failed: %v", err)
		}

		// List all assets
		assets, err := s.ListAssets("", "")
		if err != nil {
			t.Fatalf("ListAssets failed: %v", err)
		}
		if len(assets) == 0 {
			t.Fatalf("expected at least 1 asset, got 0")
		}

		found := false
		for _, a := range assets {
			if a.CanonicalValue == "198.51.100.1" {
				found = true
				if len(a.CoOccurringTargets) != 2 {
					t.Errorf("expected 2 co-occurring targets for 198.51.100.1, got %d", len(a.CoOccurringTargets))
				}
			}
		}
		if !found {
			t.Errorf("expected to find 198.51.100.1 in assets")
		}

		// Filter by target
		target1Assets, err := s.ListAssets("target1.onion", "")
		if err != nil {
			t.Fatalf("ListAssets for target1 failed: %v", err)
		}
		if len(target1Assets) == 0 {
			t.Errorf("expected assets for target1.onion")
		}

		// Filter by non-existent target
		emptyAssets, err := s.ListAssets("nonexistent.onion", "")
		if err != nil {
			t.Fatalf("ListAssets for nonexistent failed: %v", err)
		}
		if len(emptyAssets) != 0 {
			t.Errorf("expected 0 assets for nonexistent target, got %d", len(emptyAssets))
		}
	}
}

func TestFileStore_TargetDirTraversalSanitization(t *testing.T) {
	tempDir := t.TempDir()
	fs := NewFileStore(tempDir)
	defer fs.Close()

	// 1. Inputs that must be rejected
	rejectInputs := []string{
		"",
		"   ",
		"..",
		"../",
		"..\\",
		"....",
		".",
	}

	for _, input := range rejectInputs {
		dir, err := fs.targetDir(input)
		if err == nil {
			t.Errorf("targetDir(%q) expected error, got %q", input, dir)
		}
	}

	// 2. Traversal inputs that are sanitized to safe subpaths inside tempDir
	traversalInputs := []string{
		"../../etc/passwd",
		"target.onion/../../escape",
		"target.onion/subpath",
		"target.onion\\windows\\system32",
	}

	for _, input := range traversalInputs {
		dir, err := fs.targetDir(input)
		if err != nil {
			// Rejecting is also safe
			continue
		}
		cleanBase := filepath.Clean(tempDir)
		rel, relErr := filepath.Rel(cleanBase, dir)
		if relErr != nil || strings.HasPrefix(rel, "..") || rel == "." {
			t.Errorf("targetDir(%q) escaped base dir: %s (rel: %s)", input, dir, rel)
		}
	}

	// 3. Verify Save with traversal target fails or writes strictly within tempDir
	saveTarget := model.ScanResult{
		Target:    model.Target{Onion: "../../escaping"},
		StartedAt: time.Now(),
		EndedAt:   time.Now(),
	}
	savedPath, err := fs.Save(saveTarget)
	if err == nil {
		cleanBase := filepath.Clean(tempDir)
		rel, relErr := filepath.Rel(cleanBase, savedPath)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			t.Errorf("Save written outside tempDir: %s", savedPath)
		}
	}
}

func TestSQLiteStore_ConnectionPoolSettings(t *testing.T) {
	tempDir := t.TempDir()
	store, err := OpenSQLite(filepath.Join(tempDir, "testpool.db"))
	if err != nil {
		t.Fatalf("OpenSQLite failed: %v", err)
	}
	defer store.Close()

	stats := store.db.Stats()
	if stats.MaxOpenConnections != 1 {
		t.Errorf("expected MaxOpenConnections=1, got %d", stats.MaxOpenConnections)
	}
}

func TestSQLiteStore_ConcurrentSaves(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "concurrent_saves.db")
	store, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLite failed: %v", err)
	}
	defer store.Close()

	const numWorkers = 10
	const scansPerWorker = 3
	var wg sync.WaitGroup
	errCh := make(chan error, numWorkers*scansPerWorker)

	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for s := 0; s < scansPerWorker; s++ {
				onion := fmt.Sprintf("target-%d.onion", workerID)
				scan := model.ScanResult{
					Target:    model.Target{Onion: onion},
					StartedAt: now.Add(time.Duration(s) * time.Minute),
					EndedAt:   now.Add(time.Duration(s)*time.Minute + 30*time.Second),
					RiskScore: (workerID*10 + s) % 100,
					PagesSeen: 5,
					Findings: []model.Finding{
						{
							ID:         "INFRA-001",
							Title:      "IP address reference",
							Severity:   model.SeverityMedium,
							Confidence: 0.8,
							Evidence: []model.Evidence{
								{
									Type:        model.EvidenceIP,
									Description: fmt.Sprintf("198.51.100.%d", workerID),
									Source:      fmt.Sprintf("http://%s/page", onion),
								},
							},
						},
						{
							ID:         "OPSEC-002",
							Title:      "Email disclosed",
							Severity:   model.SeverityLow,
							Confidence: 0.9,
							Evidence: []model.Evidence{
								{
									Type:        model.EvidenceEmail,
									Description: fmt.Sprintf("admin@target-%d.com", workerID),
									Source:      fmt.Sprintf("http://%s/contact", onion),
								},
							},
						},
					},
				}

				if _, err := store.Save(scan); err != nil {
					errCh <- fmt.Errorf("worker %d save %d: %w", workerID, s, err)
					return
				}
			}
		}(w)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent save error: %v", err)
	}

	// Verify all targets were recorded
	targets, err := store.Targets()
	if err != nil {
		t.Fatalf("Targets failed: %v", err)
	}
	if len(targets) != numWorkers {
		t.Errorf("expected %d targets, got %d", numWorkers, len(targets))
	}
}

// ---------------------------------------------------------------------------
// Pagination tests — storage layer
// ---------------------------------------------------------------------------

func makeTargets(t *testing.T, store *SQLiteStore, onions []string) {
	t.Helper()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, onion := range onions {
		res := model.ScanResult{
			Target:    model.Target{Onion: onion},
			StartedAt: now,
			EndedAt:   now.Add(time.Minute),
			RiskScore: 10,
		}
		if _, err := store.Save(res); err != nil {
			t.Fatalf("Save(%s) failed: %v", onion, err)
		}
		now = now.Add(2 * time.Minute)
	}
}

func TestSQLiteStore_CountTargets(t *testing.T) {
	store, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite failed: %v", err)
	}
	defer store.Close()

	n, err := store.CountTargets()
	if err != nil {
		t.Fatalf("CountTargets failed: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 before any targets, got %d", n)
	}

	onions := []string{"aaa.onion", "bbb.onion", "ccc.onion", "ddd.onion", "eee.onion"}
	makeTargets(t, store, onions)

	n, err = store.CountTargets()
	if err != nil {
		t.Fatalf("CountTargets failed: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 targets, got %d", n)
	}
}

func TestSQLiteStore_TargetsPage(t *testing.T) {
	store, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite failed: %v", err)
	}
	defer store.Close()

	onions := []string{"aaa.onion", "bbb.onion", "ccc.onion", "ddd.onion", "eee.onion"}
	makeTargets(t, store, onions)

	// Page 1: limit=2, offset=0
	page1, err := store.TargetsPage(2, 0)
	if err != nil {
		t.Fatalf("TargetsPage(2, 0) failed: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(page1))
	}
	if page1[0] != "aaa.onion" || page1[1] != "bbb.onion" {
		t.Errorf("unexpected page1: %v", page1)
	}

	// Page 2: limit=2, offset=2
	page2, err := store.TargetsPage(2, 2)
	if err != nil {
		t.Fatalf("TargetsPage(2, 2) failed: %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(page2))
	}
	if page2[0] != "ccc.onion" || page2[1] != "ddd.onion" {
		t.Errorf("unexpected page2: %v", page2)
	}

	// Page 3: limit=2, offset=4 (last element only)
	page3, err := store.TargetsPage(2, 4)
	if err != nil {
		t.Fatalf("TargetsPage(2, 4) failed: %v", err)
	}
	if len(page3) != 1 {
		t.Fatalf("expected 1 target, got %d", len(page3))
	}
	if page3[0] != "eee.onion" {
		t.Errorf("expected eee.onion, got %s", page3[0])
	}

	// Offset beyond total — expect empty
	page4, err := store.TargetsPage(2, 10)
	if err != nil {
		t.Fatalf("TargetsPage(2, 10) failed: %v", err)
	}
	if len(page4) != 0 {
		t.Errorf("expected 0 targets for offset beyond total, got %d", len(page4))
	}

	// Deterministic: calling twice returns same order
	dup1, _ := store.TargetsPage(5, 0)
	dup2, _ := store.TargetsPage(5, 0)
	if len(dup1) != len(dup2) {
		t.Errorf("expected same length on duplicate call")
	}
	for i := range dup1 {
		if dup1[i] != dup2[i] {
			t.Errorf("ordering not deterministic at index %d: %s vs %s", i, dup1[i], dup2[i])
		}
	}

	// Verify no overlap between consecutive pages
	seen := make(map[string]bool)
	for _, p := range [][]string{page1, page2, page3} {
		for _, addr := range p {
			if seen[addr] {
				t.Errorf("duplicate target across pages: %s", addr)
			}
			seen[addr] = true
		}
	}
}

func TestSQLiteStore_FindingsPage_Basic(t *testing.T) {
	store, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite failed: %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// Create 3 targets, each with 3 findings in their latest scan
	for i := 0; i < 3; i++ {
		onion := fmt.Sprintf("target-%02d.onion", i)
		findings := []model.Finding{
			{ID: fmt.Sprintf("F%d-1", i), Title: "Finding A", Severity: model.SeverityHigh, Analyzer: "headers", Target: onion},
			{ID: fmt.Sprintf("F%d-2", i), Title: "Finding B", Severity: model.SeverityMedium, Analyzer: "opsec", Target: onion},
			{ID: fmt.Sprintf("F%d-3", i), Title: "Finding C", Severity: model.SeverityLow, Analyzer: "headers", Target: onion},
		}
		res := model.ScanResult{
			Target:    model.Target{Onion: onion},
			StartedAt: now,
			EndedAt:   now.Add(time.Minute),
			Findings:  findings,
		}
		if _, err := store.Save(res); err != nil {
			t.Fatalf("Save failed: %v", err)
		}
		now = now.Add(5 * time.Minute)
	}

	// Total findings: 3 targets × 3 findings = 9
	filter := FindingsFilter{}

	// Get all (limit > total)
	all, total, err := store.FindingsPage(filter, 50, 0)
	if err != nil {
		t.Fatalf("FindingsPage failed: %v", err)
	}
	if total != 9 {
		t.Errorf("expected total=9, got %d", total)
	}
	if len(all) != 9 {
		t.Errorf("expected 9 findings, got %d", len(all))
	}

	// Page 1: limit=4, offset=0
	p1, tot1, err := store.FindingsPage(filter, 4, 0)
	if err != nil {
		t.Fatalf("FindingsPage page1 failed: %v", err)
	}
	if tot1 != 9 {
		t.Errorf("expected total=9, got %d", tot1)
	}
	if len(p1) != 4 {
		t.Errorf("expected 4 findings on page1, got %d", len(p1))
	}

	// Page 2: limit=4, offset=4
	p2, tot2, err := store.FindingsPage(filter, 4, 4)
	if err != nil {
		t.Fatalf("FindingsPage page2 failed: %v", err)
	}
	if tot2 != 9 {
		t.Errorf("expected total=9, got %d", tot2)
	}
	if len(p2) != 4 {
		t.Errorf("expected 4 findings on page2, got %d", len(p2))
	}

	// Page 3: limit=4, offset=8 (only 1 left)
	p3, tot3, err := store.FindingsPage(filter, 4, 8)
	if err != nil {
		t.Fatalf("FindingsPage page3 failed: %v", err)
	}
	if tot3 != 9 {
		t.Errorf("expected total=9, got %d", tot3)
	}
	if len(p3) != 1 {
		t.Errorf("expected 1 finding on page3, got %d", len(p3))
	}

	// No duplicates across pages
	seen := make(map[string]bool)
	for _, f := range append(append(p1, p2...), p3...) {
		if seen[f.ID] {
			t.Errorf("duplicate finding ID across pages: %s", f.ID)
		}
		seen[f.ID] = true
	}

	// Offset beyond total
	beyondPage, beyondTotal, err := store.FindingsPage(filter, 4, 100)
	if err != nil {
		t.Fatalf("FindingsPage beyond total failed: %v", err)
	}
	if beyondTotal != 9 {
		t.Errorf("expected total=9 even beyond offset, got %d", beyondTotal)
	}
	if len(beyondPage) != 0 {
		t.Errorf("expected 0 findings beyond offset, got %d", len(beyondPage))
	}
}

func TestSQLiteStore_FindingsPage_Filters(t *testing.T) {
	store, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite failed: %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	onion := "filter-test.onion"
	findings := []model.Finding{
		{ID: "H1", Severity: model.SeverityHigh, Analyzer: "headers", Target: onion},
		{ID: "H2", Severity: model.SeverityHigh, Analyzer: "opsec", Target: onion},
		{ID: "M1", Severity: model.SeverityMedium, Analyzer: "headers", Target: onion},
		{ID: "L1", Severity: model.SeverityLow, Analyzer: "headers", Target: onion},
	}
	res := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: now,
		EndedAt:   now.Add(time.Minute),
		Findings:  findings,
	}
	if _, err := store.Save(res); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Severity filter
	highOnly, total, err := store.FindingsPage(FindingsFilter{Severity: "HIGH"}, 10, 0)
	if err != nil {
		t.Fatalf("FindingsPage severity failed: %v", err)
	}
	if total != 2 {
		t.Errorf("expected total=2 for HIGH severity, got %d", total)
	}
	if len(highOnly) != 2 {
		t.Errorf("expected 2 HIGH findings, got %d", len(highOnly))
	}
	for _, f := range highOnly {
		if f.Severity != model.SeverityHigh {
			t.Errorf("expected HIGH severity, got %s", f.Severity)
		}
	}

	// Analyzer filter
	headersOnly, total2, err := store.FindingsPage(FindingsFilter{Analyzer: "headers"}, 10, 0)
	if err != nil {
		t.Fatalf("FindingsPage analyzer failed: %v", err)
	}
	if total2 != 3 {
		t.Errorf("expected total=3 for headers analyzer, got %d", total2)
	}
	if len(headersOnly) != 3 {
		t.Errorf("expected 3 headers findings, got %d", len(headersOnly))
	}

	// Target filter
	targetOnly, total3, err := store.FindingsPage(FindingsFilter{Target: onion}, 10, 0)
	if err != nil {
		t.Fatalf("FindingsPage target failed: %v", err)
	}
	if total3 != 4 {
		t.Errorf("expected total=4 for target filter, got %d", total3)
	}
	if len(targetOnly) != 4 {
		t.Errorf("expected 4 findings for target, got %d", len(targetOnly))
	}

	// Multiple filters: HIGH severity + headers analyzer
	combo, total4, err := store.FindingsPage(FindingsFilter{Severity: "HIGH", Analyzer: "headers"}, 10, 0)
	if err != nil {
		t.Fatalf("FindingsPage combo failed: %v", err)
	}
	if total4 != 1 {
		t.Errorf("expected total=1 for HIGH+headers, got %d", total4)
	}
	if len(combo) != 1 || combo[0].ID != "H1" {
		t.Errorf("expected H1 finding, got %v", combo)
	}

	// Non-existent target returns 0
	missing, total5, err := store.FindingsPage(FindingsFilter{Target: "nonexistent.onion"}, 10, 0)
	if err != nil {
		t.Fatalf("FindingsPage missing target failed: %v", err)
	}
	if total5 != 0 || len(missing) != 0 {
		t.Errorf("expected empty for missing target, got total=%d, len=%d", total5, len(missing))
	}
}

func TestSQLiteStore_FindingsPage_LatestScanOnly(t *testing.T) {
	// Verify that FindingsPage only looks at the latest scan per target,
	// not older scans. This is the key correctness property.
	store, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite failed: %v", err)
	}
	defer store.Close()

	onion := "latest-test.onion"
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// Old scan with HIGH finding
	old := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: now,
		EndedAt:   now.Add(time.Minute),
		Findings: []model.Finding{
			{ID: "OLD-HIGH", Severity: model.SeverityHigh, Analyzer: "headers", Target: onion},
		},
	}
	if _, err := store.Save(old); err != nil {
		t.Fatalf("Save old scan: %v", err)
	}

	// Latest scan: only LOW findings
	latest := model.ScanResult{
		Target:    model.Target{Onion: onion},
		StartedAt: now.Add(10 * time.Minute),
		EndedAt:   now.Add(11 * time.Minute),
		Findings: []model.Finding{
			{ID: "NEW-LOW", Severity: model.SeverityLow, Analyzer: "opsec", Target: onion},
		},
	}
	if _, err := store.Save(latest); err != nil {
		t.Fatalf("Save latest scan: %v", err)
	}

	// FindingsPage should only see the latest scan's findings
	highFindings, total, err := store.FindingsPage(FindingsFilter{Severity: "HIGH"}, 10, 0)
	if err != nil {
		t.Fatalf("FindingsPage: %v", err)
	}
	if total != 0 || len(highFindings) != 0 {
		t.Errorf("expected 0 HIGH findings (old scan), got total=%d, len=%d", total, len(highFindings))
	}

	allFindings, total2, err := store.FindingsPage(FindingsFilter{}, 10, 0)
	if err != nil {
		t.Fatalf("FindingsPage all: %v", err)
	}
	if total2 != 1 {
		t.Errorf("expected 1 finding from latest scan, got %d", total2)
	}
	if len(allFindings) != 1 || allFindings[0].ID != "NEW-LOW" {
		t.Errorf("expected NEW-LOW finding, got %v", allFindings)
	}
}
