# Security Policy

## Supported Versions

This project currently supports the latest `main` branch and the `v1.x` release line.

## Reporting a Vulnerability

Please do not open public issues for vulnerabilities that could expose users or infrastructure.

Instead:

1. Prepare a private report with reproduction steps, impact, and proposed mitigation.
2. Send it to the project maintainer through a private channel.
3. Allow reasonable time for validation and remediation before public disclosure.

## Secure Deployment Guidance

- Run SentinelMesh in a segmented lab or cloud sandbox.
- Do not expose it from a workstation that stores personal files or credentials.
- Keep Docker images and Python dependencies patched.
- Rotate any intelligence API keys placed in `.env`.
