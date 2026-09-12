# Contributing to OnionSec

Thank you for your interest in contributing to OnionSec. We value high-quality, well-tested contributions that enhance security observability and privacy defense.

This document provides guidelines for environment setup, coding conventions, testing procedures, and submission workflows.

---

## Code of Conduct

All contributors and maintainers are expected to adhere to the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md). Please report any violations through repository security or moderation channels.

---

## Getting Started

### Prerequisites

- **Go 1.22+**: [Install Go](https://go.dev/dl/)
- **C Compiler (CGO)**: SQLite persistence requires `CGO_ENABLED=1` (`gcc` on Linux, `clang` on macOS).
- **Git**: Ensure your local Git identity is configured with a verified email.
- **Node.js 20+ & npm**: Required only if modifying the web dashboard in `web/`.
- **Tor Daemon**: Required for end-to-end integration testing (`127.0.0.1:9050`).

### Fork & Clone

```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork locally
git clone https://github.com/<your-username>/OnionScan.git
cd OnionScan

# 3. Add the upstream remote
git remote add upstream https://github.com/FLATLINEDSTAR/OnionScan.git
```

---

## Development Workflow

### 1. Issue First Policy
Before embarking on major work or new analyzers, check the [Issue Tracker](https://github.com/FLATLINEDSTAR/OnionScan/issues). If an issue already exists, comment on it to signal your intent to work on it. If not, please open an issue to discuss your proposal first.

### 2. Branching Conventions
Create a descriptive feature branch from `main`:
```bash
git checkout -b fix/sqlite-foreign-keys
# or
git checkout -b feat/tls-weak-ciphers
# or
git checkout -b docs/architecture-diagrams
```

Prefix conventions:
- `feat/`: New features, commands, or analyzers
- `fix/`: Bug fixes and error handling corrections
- `refactor/`: Code reorganization without behavioral change
- `docs/`: Documentation updates and corrections
- `test/`: Adding or improving test cases
- `ci/`: GitHub Actions workflows and build automation

### 3. Commit Message Standards
We follow Conventional Commits:
```
<type>(<scope>): <short summary in imperative mood>

[optional body explaining problem and rationale]

[optional footer: Closes #<issue-number>]
```
Examples:
- `fix(storage): enable foreign key constraints in sqlite connection dsn`
- `feat(analyzer): add weak cipher suite detection to tls analyzer`
- `test(api): add pagination tests for targets and findings endpoints`

---

## Adding a Modular Analyzer

Analyzers are the most common and impactful way to contribute:

1. Create a directory under `internal/analyzer/<name>/`.
2. Implement the `analyzer.Analyzer` interface defined in `internal/analyzer/analyzer.go`:
   ```go
   type Analyzer interface {
       Name() string
       Analyze(ctx context.Context, target model.Target, page model.Page) ([]model.Finding, error)
   }
   ```
3. Register your analyzer in `internal/scan/scan.go`'s `DefaultRegistry()`.
4. Define your rule IDs and confidence metrics in `docs/RULES.md` and `docs/RULE_CONTRIBUTIONS.md`.
5. Add unit tests (`<name>_test.go`) with table-driven tests covering true-positive and true-negative cases.

---

## Quality Bar & Verification

Before opening a pull request, run all checks locally:

```bash
# 1. Format code according to Go standard
gofmt -w .

# 2. Run static analysis
go vet ./...

# 3. Run the Go test suite with the race detector
go test -v -race ./...

# 4. If modifying the web dashboard, verify the build
cd web
npm ci
npm run build
cd ..
```

---

## Pull Request Submission

1. Ensure your branch is rebased on the latest `upstream/main`:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```
2. Push your branch to your fork:
   ```bash
   git push origin <branch-name>
   ```
3. Open a Pull Request against `FLATLINEDSTAR/OnionScan:main`.
4. Complete the Pull Request template checklist thoroughly.
5. Automated CI checks will run. If tests fail, review the logs and update your branch.

---

## Security Reporting

**Never file public issues for security vulnerabilities in OnionSec or active targets.**  
Please report security vulnerabilities privately via [GitHub Security Advisories](https://github.com/FLATLINEDSTAR/OnionScan/security/advisories/new). See [`SECURITY.md`](SECURITY.md) for full details.
