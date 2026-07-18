# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.3.x   | Yes                |
| 0.2.x   | Yes                |
| 0.1.x   | No                 |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, please use one of the following methods:

1. **GitHub Private Vulnerability Reporting:** Use the "Report a vulnerability" button on the [Security tab](https://github.com/hermes-labs-ai/little-canary/security/advisories/new) of this repository.

2. **Email:** Send details to `lpcisystems@gmail.com`.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response expectations

Reports are handled on a best-effort basis. This project does not currently
promise a fixed acknowledgment or resolution service level.

### Disclosure Policy

We follow coordinated disclosure. After a fix is released, we will:
- Publish a GitHub Security Advisory
- Credit the reporter (with consent)
- Update the CHANGELOG

## Security Design Notes

Little Canary is a security risk sensor with a **fail-open** design: if an enabled canary or configured analysis dependency fails, routing may still return `safe=True`. The same result is marked `degraded=True`, reports the failed coverage state, and leaves the unavailable risk measurement as `null`. Treat degraded traffic as uninspected pass-through, not as a clean security verdict. Deployments should use `pipeline.health_check()` at startup and monitor readiness and degradation.

Little Canary does not give its canary tools, application credentials, or output execution. The default pipeline removes response and signal-evidence bytes from callback/serialized layer snapshots and does not automatically forward canary output. Low-level probe/analysis objects do retain it for analysis and must be treated as sensitive. That library boundary is narrower than an operating-system sandbox. The selected backend receives raw input; an optional judge also receives the canary response.
