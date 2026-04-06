# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `prompt-defense-audit`, please report it responsibly.

**Do not open a public GitHub issue.**

Email: **dev@ultralab.tw**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Scope

This package is a **static analysis tool** — it scans prompt text using regex patterns. It does not:
- Execute prompts against LLMs
- Send data to external services
- Store or transmit user data

Security concerns most relevant to this project:
- **False negatives** — a defense pattern that should be detected but isn't (could give false confidence)
- **ReDoS** — regex patterns that could be exploited for denial-of-service via catastrophic backtracking
- **Supply chain** — compromised dependencies (we maintain zero runtime dependencies to minimize this risk)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | No        |
