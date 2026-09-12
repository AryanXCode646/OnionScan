#!/usr/bin/env bash
# Bulk-create the backlog from ISSUES.md as real GitHub issues using the
# GitHub CLI (https://cli.github.com/).
#
# Usage:
#   gh auth login                 # one-time, if not already authenticated
#   ./scripts/create_issues.sh    # run from the repo root
#
# Safe to re-run: gh issue create will just create duplicates if you run it
# twice, so only run this once per issue set (or delete/edit the labels
# array below to create a subset).

set -euo pipefail

REPO="AryanXCode646/OnionScan"

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI (gh) not found. Install it: https://cli.github.com/" >&2
  exit 1
fi

echo "Creating labels (safe if they already exist)..."
for label in phase-1 phase-2 phase-3 phase-4 phase-5 analyzer core docs good-first-issue security; do
  gh label create "$label" --repo "$REPO" --color "ededed" 2>/dev/null || true
done

create() {
  local title="$1" labels="$2" body="$3"
  echo "Creating: $title"
  gh issue create --repo "$REPO" --title "$title" --label "$labels" --body "$body"
}

# --- Phase 1 -----------------------------------------------------------
create "Add unit tests for the opsec analyzer" "phase-1,good-first-issue" \
"internal/analyzer/headers has a test file (headers_test.go) showing the expected pattern. Add an equivalent internal/analyzer/opsec/opsec_test.go covering: email detection, public IP -> INFRA-001, private/RFC1918 IP -> OPSEC-007, and a true-negative case (page with no identifiers) that produces zero findings."

create "Add unit tests for the fingerprint analyzer" "phase-1,good-first-issue" \
"Add internal/analyzer/fingerprint/fingerprint_test.go. Assert that two pages with identical headers produce the same signature, and two pages with different headers produce different signatures."

create "Add unit tests for the correlation engine" "phase-1,good-first-issue" \
"Add internal/correlation/engine_test.go. Cover: findings with IP evidence but no fingerprint evidence (no INFRA-002 emitted), and findings with both (should emit INFRA-002)."

create "Add unit tests for the crawler" "phase-1" \
"Use net/http/httptest to spin up a local test server that mimics a small site, and point crawler.Crawl at it via a plain http.Client (no Tor needed for the test). Cover: same-origin link following, respecting MaxPages, respecting MaxBodyByte via LimitReader."

create "Add unit tests for internal/storage" "phase-1,good-first-issue" \
"Cover Save -> Latest round-trip and History ordering, using t.TempDir() as the base dir."

create "Add a config file (YAML) for scan limits and Tor SOCKS address" "phase-1,core" \
"Currently crawler.DefaultLimits and tor.DefaultSOCKSAddr are hardcoded in cmd/onionsec/main.go. Add a --config flag (default ~/.onionsec/config.yaml) that can override: SOCKS address, max pages, max body size, page timeout, total budget."

create "Add --json / --md output file flags to onionsec scan" "phase-1,good-first-issue" \
"Right now onionsec scan only prints Markdown to stdout. Add flags to also (or instead) write report.WriteJSON / report.WriteMarkdown to files."

create "Add golangci-lint to CI" "phase-1,core" \
".github/workflows/ci.yml currently only runs gofmt, go vet, go build, go test. Once the analyzer set stabilizes, add golangci-lint with a reasonable default config."

# --- Phase 2 -----------------------------------------------------------
create "Implement a TLS analyzer" "phase-2,analyzer" \
"New internal/analyzer/tls/. Inspect certificates for clearnet hostnames (SEC-001) and weak/deprecated TLS config (SEC-002) where the target is reachable over HTTPS."

create "Implement a robots.txt / sitemap analyzer" "phase-2,analyzer,good-first-issue" \
"New internal/analyzer/robots/. Fetch /robots.txt and /sitemap.xml and flag disallowed paths that suggest hidden admin/debug endpoints (informational, don't auto-visit)."

create "Implement a source map / JS bundle analyzer" "phase-2,analyzer,security" \
"New internal/analyzer/jsanalysis/. Static-only analysis of .map references and inline build/framework info. Must never execute target JavaScript."

create "Implement an external-resource analyzer" "phase-2,analyzer" \
"New internal/analyzer/external/. Parse script/img/link tags pointing to a different host and record them as EvidenceExternalRes for the correlation engine."

create "Implement an API endpoint detection analyzer" "phase-2,analyzer" \
"New internal/analyzer/apidetect/. Detect common REST/GraphQL path patterns referenced in page content or discovered during crawl."

create "Implement a credential/secret pattern analyzer" "phase-2,analyzer,security" \
"New internal/analyzer/credentials/. Detect obvious secret patterns (API keys, PEM private key headers). Redact findings -- never report the full secret value."

create "Implement an EXIF/image metadata analyzer" "phase-2,analyzer" \
"New internal/analyzer/metadata/. Check images referenced by the target for EXIF GPS/camera/software metadata, respecting crawler size limits."

# --- Phase 3 -----------------------------------------------------------
create "Design the persistent evidence store schema" "phase-3,core" \
"Write docs/EVIDENCE_STORE.md describing how evidence values get indexed across scans/targets for fast cross-target lookup."

create "Implement cross-target evidence correlation" "phase-3,core" \
"Extend internal/correlation to check newly-collected evidence against the persistent store (see prior schema-design issue), not just findings within one scan."

create "Replace fixed confidence bump with a weighted scoring model" "phase-3,core" \
"internal/correlation.Correlate currently uses a flat 0.7 confidence for IP+fingerprint co-occurrence. Design and implement a weighted model that scales with the number/independence of corroborating evidence."

create "Add onionsec graph <target> command" "phase-3" \
"Render the evidence graph for a target as text (indented tree) or Graphviz DOT output."

# --- Phase 4 -----------------------------------------------------------
create "Implement onionsec monitor" "phase-4,core" \
"cmd/onionsec/main.go's cmdMonitor is currently a stub. Implement: run a new scan, load the previous scan via storage.Store.Latest, diff finding IDs/evidence, print NEW / REMOVED / CHANGED sections."

create "Migrate internal/storage to SQLite" "phase-4,core" \
"Introduce a SQLite-backed implementation behind the same Store interface once monitoring needs real queries. Document the new cgo/build requirement in README.md."

create "Add onionsec diff <target> <scan-id> <scan-id>" "phase-4" \
"Standalone comparison between two arbitrary past scans, reusing the diffing logic from the monitor implementation."

create "Add scheduled/recurring scan support" "phase-4" \
"Start with cron-friendly CLI flags before considering a long-running daemon mode."

# --- Phase 5 -----------------------------------------------------------
create "Design the HTTP API" "phase-5,core" \
"Write docs/API.md covering POST /v1/scans, GET /v1/scans/:id, GET /v1/findings, GET /v1/assets, GET /v1/history -- request/response shapes, auth approach, reuse of internal/scan and internal/storage."

create "Implement the HTTP API server" "phase-5,core" \
"Implement the API design as cmd/onionsecd/, reusing internal/scan.Run and internal/storage.Store."

create "Build the dashboard (React/Next.js)" "phase-5" \
"Consumes the HTTP API. Start with a scan list + finding detail view before the evidence graph visualization."

create "Add evidence graph visualization (Cytoscape.js)" "phase-5" \
"Depends on the text/DOT graph command and the dashboard shell. Render the evidence graph interactively."

# --- Cross-cutting -------------------------------------------------------
create "Write a community rule-contribution process" "docs,good-first-issue" \
"Document how an external contributor proposes a brand-new rule ID range when adding a whole new analyzer category, to avoid ID collisions across concurrent PRs."

create "Add a SECURITY.md" "docs,good-first-issue" \
"Add a SECURITY.md with supported versions and a disclosure timeline expectation for vulnerabilities in OnionSec itself."

create "Rename module path if/when the repo is renamed away from OnionScan" "docs" \
"See docs/ARCHITECTURE.md 'Naming note'. Tracked so it isn't forgotten if the repository is later renamed."

echo "Done. Created 30 issues in $REPO."
