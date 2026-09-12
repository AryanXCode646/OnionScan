## Summary
<!-- Concise 1-2 sentence overview of the pull request. Closes #<issue-number> -->

## Problem
<!-- What limitation, defect, or architectural gap does this PR address? -->

## Solution
<!-- How does this PR resolve the problem? High-level technical approach. -->

## Changes
<!-- Bullet points detailing specific file and module modifications. -->
- 

## Testing
<!-- How was this change validated? List test cases, mock servers, or commands run. -->
- [ ] Unit tests added / updated
- [ ] Local build and test suite executed (`go test -v -race ./...`)
- [ ] Web dashboard build verified (if modifying `web/`: `npm run build`)

## Security Considerations
<!-- Does this change handle untrusted inputs, alter network routing, modify crawler boundaries, or touch sensitive storage? -->
- 

## Breaking Changes
<!-- Does this change introduce breaking changes to the CLI flags, REST API schemas, or SQLite database tables? -->
- 

## Documentation
<!-- Have relevant docs (README.md, docs/ARCHITECTURE.md, docs/RULES.md, docs/API.md) been updated? -->
- 

## Contributor Checklist
- [ ] Code adheres to formatting standards (`gofmt -l .` returns clean)
- [ ] Static analysis passes (`go vet ./...`, `golangci-lint`)
- [ ] All existing and new tests pass cleanly
- [ ] No hardcoded secrets, tokens, or private network addresses committed
- [ ] No unnecessary external dependencies introduced
- [ ] Boundary limits (crawler size, timeouts, same-origin) maintained
