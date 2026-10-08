# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

Only the latest `1.0.x` release is supported with security updates.
Pre-1.0 code (including all Git history before `v1.0.0`) is considered
compromised for the two practice credentials and must not be deployed.

## Reporting a Vulnerability

**Do not open a public Issue** with exploit details. Report privately through
the repository's private vulnerability reporting channel:

1. Open the repository page on GitHub.
2. Go to the **Security** tab → **Advisories** → **Report a vulnerability**
   (direct link: https://github.com/Tonsete/reportaudit-lab/security/advisories/new).
3. Describe the affected version, the steps to reproduce in general terms
   and your contact address.

You will receive a first response within 5 working days. Coordinated
disclosure: the report stays private until a fix is merged and released,
with a target of 30 days for High severity or lower.

## What to expect

- Vulnerabilities in ReportAudit's own code (SAST) are fixed in code and
  covered by the required pipeline checks.
- Vulnerabilities in dependencies (SCA) are fixed by upgrading, preferably
  through the grouped Dependabot security updates.
- Credentials found in the repository or its history are treated as
  compromised: they are rotated, never just deleted.

## Scope

In scope: `app/`, `requirements.txt` and the release SBOM.
Out of scope: `tools/` binaries, the local `reportes.db` and `.env` files.
