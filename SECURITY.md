# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
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

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Status update:** Within 14 days
- **Resolution target:** Within 90 days

### Disclosure Policy

We follow coordinated disclosure. After a fix is released, we will:
- Publish a GitHub Security Advisory
- Credit the reporter (with consent)
- Update the CHANGELOG

## Security Design Notes

Little Canary is a security tool with a **fail-open** design: if the canary model or Ollama is unavailable, inputs pass through unscreened. This is a deliberate availability-over-security tradeoff. Deployments should use `pipeline.health_check()` at startup and monitor canary availability in production.

The canary model has zero permissions — its output is never executed or forwarded to production systems. It exists only to be observed.
