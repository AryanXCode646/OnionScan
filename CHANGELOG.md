# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Next.js and TypeScript build and typecheck validation in GitHub Actions CI workflow (`web-ci` job).
- Dependabot configuration for automated Go modules, npm packages, and GitHub Actions updates.
- Standardized GitHub issue form templates (`bug_report.yml`, `feature_request.yml`, `documentation.yml`, `rfc.yml`) and `config.yml`.
- Contributor Covenant v2.1 `CODE_OF_CONDUCT.md`.
- Graceful shutdown and cancellation handling via `SIGINT` / `SIGTERM` in `onionsec scan` CLI.
- Foreign key constraint enforcement (`_foreign_keys=ON`) in SQLite connection strings.
- Pagination query parameters (`limit`, `offset`) and total count metadata for `/v1/findings` and `/v1/targets` endpoints.
- Error boundary and defensive edge filtering in `EvidenceGraph` Cytoscape component.

### Fixed
- Fixed SQLite referential integrity where cascade deletions were ignored due to disabled foreign keys.
- Fixed premature timeout aborts in `onionsecd` HTTP server during multi-minute synchronous scans.
- Fixed unhandled Cytoscape render crashes caused by orphaned edges in graph visualization.
- Portable `sed -i` in `scripts/rename_module.sh` for cross-platform macOS/BSD compatibility.

---

## [0.1.0-alpha] - 2026-09-12

### Added
- Core scanner engine with modular analyzer pipeline (`internal/analyzer`).
- Built-in analyzers:
  - Headers analyzer (server identification, missing security headers).
  - OPSEC analyzer (email disclosures, public IP addresses, RFC1918 private IPs).
  - Fingerprint analyzer (HTTP header hash generation).
  - API detection analyzer (endpoint route discovery).
  - Credentials analyzer (AWS keys, GitHub tokens, generic API credentials).
  - External resources analyzer (clearnet asset leaks).
  - JavaScript analyzer (source map disclosures).
  - Metadata analyzer (EXIF and image metadata exposure).
  - Robots analyzer (`robots.txt` and `sitemap.xml` inspection).
  - TLS analyzer (certificate hostnames, expiry, weak ciphers).
- Native, dependency-free Tor SOCKS5 CONNECT client with domain-name resolution.
- Bounded same-origin crawler with strict limits (depth, size, timeout, same-origin redirect policy).
- Evidence correlation engine with multi-point weighted confidence scoring.
- SQLite-backed persistent evidence store with WAL mode and serialized connection pooling.
- CLI subcommands: `scan`, `report`, `monitor`, `diff`, and `graph`.
- Daemon HTTP server (`onionsecd`) with `/v1/targets`, `/v1/scans`, `/v1/findings`, `/v1/graph`, and `/v1/assets`.
- Next.js web dashboard with Cytoscape interactive evidence graph and scan management.
