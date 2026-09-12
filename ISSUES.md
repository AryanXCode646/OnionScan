# Issue backlog

This is the full backlog behind `docs/ROADMAP.md`, written as ready-to-paste
GitHub issues. Use `scripts/create_issues.sh` to create them all at once via
the GitHub CLI, or copy sections manually. Each has a suggested title,
labels, and body — trim/adjust as you actually work through them.

Recommended labels to create in the repo first: `phase-1`, `phase-2`,
`phase-3`, `phase-4`, `phase-5`, `analyzer`, `core`, `docs`,
`good-first-issue`, `security`.

---

## Phase 1 — MVP hardening

### 1. Add unit tests for the opsec analyzer
Labels: `phase-1`, `good-first-issue`
Body:
`internal/analyzer/headers` has a test file (`headers_test.go`) showing the
expected pattern. Add an equivalent `internal/analyzer/opsec/opsec_test.go`
covering: email detection, public IP → `INFRA-001`, private/RFC1918 IP →
`OPSEC-007`, and a true-negative case (page with no identifiers) that
produces zero findings.

### 2. Add unit tests for the fingerprint analyzer
Labels: `phase-1`, `good-first-issue`
Body:
Add `internal/analyzer/fingerprint/fingerprint_test.go`. Assert that two
pages with identical headers produce the same signature, and two pages
with different headers produce different signatures.

### 3. Add unit tests for the correlation engine
Labels: `phase-1`, `good-first-issue`
Body:
Add `internal/correlation/engine_test.go`. Cover: findings with IP evidence
but no fingerprint evidence (no `INFRA-002` emitted), and findings with
both (should emit `INFRA-002`).

### 4. Add unit tests for the crawler
Labels: `phase-1`
Body:
Use `net/http/httptest` to spin up a local test server that mimics a small
site, and point `crawler.Crawl` at it via a plain `http.Client` (no Tor
needed for the test). Cover: same-origin link following, respecting
`MaxPages`, respecting `MaxBodyByte` via `LimitReader`.

### 5. Add unit tests for internal/storage
Labels: `phase-1`, `good-first-issue`
Body:
Cover `Save` → `Latest` round-trip and `History` ordering, using `t.TempDir()`
as the base dir.

### 6. Add a config file (YAML) for scan limits and Tor SOCKS address
Labels: `phase-1`, `core`
Body:
Currently `crawler.DefaultLimits` and `tor.DefaultSOCKSAddr` are hardcoded
in `cmd/onionsec/main.go`. Add a `--config` flag (default
`~/.onionsec/config.yaml`) that can override: SOCKS address, max pages,
max body size, page timeout, total budget. Keep parsing dependency-free
(hand-rolled minimal YAML/key-value, or defer to a documented external dep
in a separate discussion issue if a real YAML parser is wanted).

### 7. Add `--json` / `--md` output file flags to `onionsec scan`
Labels: `phase-1`, `good-first-issue`
Body:
Right now `onionsec scan` only prints Markdown to stdout. Add flags to also
(or instead) write `report.WriteJSON` / `report.WriteMarkdown` to files, per
the usage comment already in `cmd/onionsec/main.go`.

### 8. Add `golangci-lint` to CI
Labels: `phase-1`, `core`
Body:
`.github/workflows/ci.yml` currently only runs `gofmt`, `go vet`, `go build`,
`go test`. Once the analyzer set stabilizes, add `golangci-lint` with a
reasonable default config.

---

## Phase 2 — Security engine

### 9. Implement a TLS analyzer
Labels: `phase-2`, `analyzer`
Body:
New `internal/analyzer/tls/`. If the target is reachable over HTTPS,
inspect the certificate: subject/SAN hostnames (useful for correlation if a
clearnet hostname appears), issuer, expiry, and weak cipher suites. Emit
`SEC-001` (cert issued to a clearnet hostname) and `SEC-002` (weak/deprecated
TLS config). Note the crawler currently only fetches over `http://` for
onion services — check whether the target also serves HTTPS internally
before assuming this analyzer applies.

### 10. Implement a robots.txt / sitemap analyzer
Labels: `phase-2`, `analyzer`, `good-first-issue`
Body:
New `internal/analyzer/robots/`. Fetch `/robots.txt` and `/sitemap.xml`
during the crawl (or as a dedicated pre-crawl step) and flag disallowed
paths that suggest hidden admin/debug endpoints worth noting as `OPSEC-004`
candidates (informational — don't auto-visit disallowed paths).

### 11. Implement a source map / JS bundle analyzer
Labels: `phase-2`, `analyzer`, `security`
Body:
New `internal/analyzer/jsanalysis/`. Static-only: look for `.map` file
references, inline comments revealing framework/build info, and hardcoded
API endpoints. Must not execute any JavaScript — see
`docs/ARCHITECTURE.md` Safety rules.

### 12. Implement an external-resource analyzer
Labels: `phase-2`, `analyzer`
Body:
New `internal/analyzer/external/`. Parse `<script src>`, `<img src>`,
`<link href>` pointing to a different host than the target and record them
as `EvidenceExternalRes`. This is what powers "14 external resources
detected" style output from the design doc and feeds the Phase 3
evidence graph.

### 13. Implement an API endpoint detection analyzer
Labels: `phase-2`, `analyzer`
Body:
New `internal/analyzer/apidetect/`. Look for common REST/GraphQL path
patterns (`/api/`, `/graphql`, `/v1/`, `/wp-json/`, etc.) referenced in
page content or discovered during the crawl, and record them as
informational findings useful for the correlation engine later.

### 14. Implement a credential/secret pattern analyzer
Labels: `phase-2`, `analyzer`, `security`
Body:
New `internal/analyzer/credentials/`. Detect obvious secret patterns (AWS
key prefixes, generic `api_key=`/`token=` assignments, PEM private key
headers). **Redact findings**: report the pattern type and a truncated/
hashed value, never the full secret — see `docs/ARCHITECTURE.md` Safety
rules and `docs/RULES.md` `CRED-001`/`CRED-002`.

### 15. Implement an EXIF/image metadata analyzer
Labels: `phase-2`, `analyzer`
Body:
New `internal/analyzer/metadata/`. Download images referenced by the
target (respecting crawler size limits) and check for EXIF GPS/camera/
software metadata. Standard library `image` package can decode headers;
evaluate whether EXIF parsing needs a small dependency (flag in the PR if
so, per `CONTRIBUTING.md`'s dependency policy).

---

## Phase 3 — Correlation engine (the differentiator)

### 16. Design the persistent evidence store schema
Labels: `phase-3`, `core`
Body:
Before implementing cross-target correlation, write a short design doc
(`docs/EVIDENCE_STORE.md`) describing how evidence values (IPs, cert
fingerprints, response signatures) get indexed across scans/targets so
"have we seen this elsewhere?" is a fast lookup, not an O(n) scan of every
past result.

### 17. Implement cross-target evidence correlation
Labels: `phase-3`, `core`
Body:
Building on #16, extend `internal/correlation` to check newly-collected
evidence against the persistent store, not just findings within the same
scan. Emit a new finding type when the same fingerprint/IP/cert appears
across two different `.onion` targets the user has scanned.

### 18. Replace fixed confidence bump with a weighted scoring model
Labels: `phase-3`, `core`
Body:
`internal/correlation.Correlate` currently uses a flat `0.7` confidence
when IP + fingerprint evidence co-occur. Design and implement a weighted
model (see the design doc's evidence-graph example) where confidence scales
with the number and independence of corroborating evidence types.

### 19. Add `onionsec graph <target>` command
Labels: `phase-3`
Body:
Render the evidence graph for a target as text (indented tree, matching the
style in the original design doc) or Graphviz DOT output. This is the
CLI-first stepping stone before the Phase 5 Cytoscape.js visualization.

---

## Phase 4 — Monitoring

### 20. Implement `onionsec monitor`
Labels: `phase-4`, `core`
Body:
`cmd/onionsec/main.go`'s `cmdMonitor` is currently a stub. Implement: run a
new scan, load the previous scan via `storage.Store.Latest`, diff finding
IDs and evidence, and print NEW / REMOVED / CHANGED sections (see the
"Day 1 / Day 7" example in the original design notes).

### 21. Migrate internal/storage to SQLite
Labels: `phase-4`, `core`
Body:
Once monitoring needs real queries (e.g. "show me every scan where
INFRA-002 fired in the last 30 days"), the current one-JSON-file-per-scan
approach won't scale well. Introduce a SQLite-backed implementation behind
the same `Store` interface used by `internal/scan` and `cmd/onionsec`, and
document the new cgo/build requirement in `README.md`.

### 22. Add `onionsec diff <target> <scan-id> <scan-id>`
Labels: `phase-4`
Body:
Standalone comparison between two arbitrary past scans (not just
latest-vs-previous like `monitor`), using the same diffing logic from #20.

### 23. Add scheduled/recurring scan support
Labels: `phase-4`
Body:
Start with cron-friendly CLI flags (e.g. an exit code / output mode
suited to being invoked from cron) before considering a long-running
daemon mode.

---

## Phase 5 — API + dashboard

### 24. Design the HTTP API
Labels: `phase-5`, `core`
Body:
Write `docs/API.md` covering `POST /v1/scans`, `GET /v1/scans/:id`,
`GET /v1/findings`, `GET /v1/assets`, `GET /v1/history` — request/response
shapes, auth approach, and how it reuses `internal/scan`, `internal/storage`.

### 25. Implement the HTTP API server
Labels: `phase-5`, `core`
Body:
Implement the design from #24 as `cmd/onionsecd/` (a separate binary from
the CLI), reusing `internal/scan.Run` and `internal/storage.Store`.

### 26. Build the dashboard (React/Next.js)
Labels: `phase-5`
Body:
Consumes the API from #25. Start with a scan list + finding detail view
before attempting the evidence graph visualization.

### 27. Add evidence graph visualization (Cytoscape.js)
Labels: `phase-5`
Body:
Depends on #19 (text/DOT graph output) and #26 (dashboard shell). Render
the evidence graph interactively in the dashboard.

---

## Cross-cutting / governance

### 28. Write a community rule-contribution process
Labels: `docs`, `good-first-issue`
Body:
`docs/RULES.md` documents the rule ID scheme. Add a short section (or a
separate `docs/RULE_CONTRIBUTIONS.md`) describing how an external
contributor proposes a brand-new rule ID range if they're adding a whole
new analyzer category, to avoid ID collisions across concurrent PRs.

### 29. Add a SECURITY.md
Labels: `docs`, `good-first-issue`
Body:
`CONTRIBUTING.md` mentions using the repo's Security tab for
vulnerabilities in OnionSec itself; add a proper `SECURITY.md` with
supported versions and a disclosure timeline expectation.

### 30. Rename module path if/when the repo is renamed away from "OnionScan"
Labels: `docs`
Body:
See `docs/ARCHITECTURE.md` "Naming note." Tracked so it doesn't get
forgotten if the repository is later renamed to avoid confusion with the
unrelated, actively-maintained OnionScan project.
