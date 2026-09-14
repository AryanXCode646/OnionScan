# Security Policy

The OnionSec project takes the security of its scanner and users seriously. As a tool designed to fetch and inspect untrusted remote content over the Tor network, maintaining scanner integrity, avoiding unintended traffic leaks, and protecting the host environment are paramount.

---

## Supported Versions

Security updates and vulnerability patches are applied to the latest development branch and official releases.

| Version | Supported          |
| ------- | ------------------ |
| `main`  | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues or discussions.**

If you discover a vulnerability in OnionSec itself:

1. **GitHub Security Advisories (Preferred):**
   - Navigate to the repository's **Security** tab.
   - Click **Report a vulnerability** to open a private advisory draft.
   - Provide a description of the issue, steps to reproduce, and any proof-of-concept code.

2. **Maintainer Contact:**
   - If GitHub Security Advisories are unavailable, contact the repository maintainers directly via their published contact channels.

### What to Include in Your Report

To help us assess and resolve the issue quickly, please include:
- A description of the vulnerability and its potential impact.
- Clear steps to reproduce or a minimal proof of concept (PoC).
- Any details regarding affected platforms, Go runtime versions, or environment configurations.
- Any suggested mitigations or patches if available.

---

## Response & Disclosure SLAs

We are committed to handling security vulnerabilities responsibly:

- **Initial Acknowledgment:** Within **48 hours** of receiving the report.
- **Triage & Assessment:** Within **5 business days**, confirming severity and reproducibility.
- **Remediation & Patching:** Maintainers will coordinate an appropriate release and CVE assignment (if applicable) prior to public disclosure.
- **Coordinated Disclosure:** We request that reporters adhere to standard coordinated vulnerability disclosure practices, allowing time for a fix to be published before public disclosure.

---

## Threat Model & Scope

### In-Scope Vulnerabilities

Vulnerabilities within the OnionSec scanner codebase and its runtime behavior are considered in-scope, including:

- **Remote Code Execution (RCE):** Execution of code or arbitrary commands on the scanner host triggered by parsing target responses, headers, or metadata.
- **Tor Isolation & Clearnet Leaks:** Bypasses in the Tor client or crawler resulting in unrouted clearnet DNS requests, HTTP connections, or socket leaks during onion scans.
- **Crawler Boundary Bypasses:** Circumvention of same-origin constraints, resource boundaries, or loop protections leading to unauthorized host access or SSRF.
- **Sensitive Data & Credential Exposure:** Scanner reports inadvertently leaking unredacted secrets or system credentials from the scanning host.
- **Parser Flaws & Denial of Service on Scanner:** Memory exhaustion, infinite loops, or unhandled panics within core parsers when processing maliciously crafted responses.

### Out-of-Scope Issues

The following areas are explicitly outside the scope of OnionSec's security model:

- Vulnerabilities or security flaws present in the remote target website or service being scanned.
- Denial-of-service (DoS) attacks directed against target onion services.
- Flaws, outages, or sybil attacks in the upstream Tor network infrastructure itself.
- Attacks requiring physical access or root compromise of the host running the scan.
- Social engineering attacks targeting maintainers or users.

---

## Safety Rules for Development

All contributions must adhere to the non-negotiable safety rules outlined in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md):

- **Never execute target JavaScript** on the scanner host.
- **Bound every crawl** (depth, pages, body sizes, and timeouts).
- **Same-origin crawl only.**
- **Redact detected credentials** in scan reports.
- **Explicit target authorization:** Only scan targets explicitly supplied by the user.
