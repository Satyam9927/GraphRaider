# Security Policy

GraphRaider is an offensive-security tool. This policy covers vulnerabilities **in
GraphRaider itself** — not in the third-party systems you point it at.

## Authorized use only

GraphRaider is intended for **authorized** security testing: systems you own or have
explicit, written permission to test (engagements, bug-bounty scope, CTFs, lab
environments). Using it against systems without authorization may be illegal. You are
solely responsible for how you use this tool.

## Supported versions

The latest release on the `main` branch is supported. Older versions are not patched —
please update before reporting.

| Version | Supported |
| ------- | --------- |
| latest (`main`) | ✅ |
| older   | ❌ |

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for a
vulnerability.

1. Preferred: open a private report via **GitHub → Security → "Report a vulnerability"**
   (GitHub Private Vulnerability Reporting) on
   [`Satyam9927/GraphRaider`](https://github.com/Satyam9927/GraphRaider/security/advisories/new).
2. Alternatively, open a regular issue that contains **no exploit details** asking a
   maintainer to open a private channel.

Please include:
- affected file(s) / component and version or commit,
- a clear description and impact,
- reproduction steps or a minimal proof of concept.

### What to expect
- Acknowledgement within a few days.
- A fix or mitigation plan once the report is triaged.
- Credit in the release notes if you'd like it.

Thanks for helping keep GraphRaider and its users safe.
