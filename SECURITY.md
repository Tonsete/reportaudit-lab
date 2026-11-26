# Security Policy

## Supported versions

| Version | Supported          | End of security support |
|---------|--------------------|-------------------------|
| 1.x     | :white_check_mark: | 2031-10-31              |
| < 1.0   | :x:                | —                       |

Pre-1.0 code (including all Git history before `v1.0.0`) contains two practice
credentials that are considered compromised and have been rotated. It must not
be deployed.

## Reporting a vulnerability

Please **do not** open a public issue. Report it privately through GitHub:
**Security → Report a vulnerability**
https://github.com/Tonsete/reportaudit-lab/security/advisories/new

Include the affected version, steps to reproduce, the impact you observed
and, if you have one, a suggested fix.

## What to expect

- Acknowledgement within **3 business days**.
- Initial assessment within **10 business days**.
- Coordinated disclosure: we aim to release a fix and publish a security
  advisory within **90 days**. We will credit you unless you prefer otherwise.

How we fix each kind of finding:

- Vulnerabilities in ReportAudit's own code (SAST) are fixed in code and
  covered by the required pipeline checks.
- Vulnerabilities in dependencies (SCA) are fixed by upgrading, preferably
  through the grouped Dependabot security updates.
- Credentials found in the repository or its history are treated as
  compromised: they are rotated, never just deleted.

## Safe harbour

We will not take legal action against researchers who act in good faith,
avoid privacy violations and service disruption, and give us reasonable
time to fix the issue before disclosing it.

## Scope

In scope: `app/`, `requirements.txt` and the release artifacts.
Out of scope: `tools/` binaries, the local `reportes.db` and `.env` files.

## Verifying our releases

Every release includes a CycloneDX SBOM, SHA-256 checksums and
Sigstore-signed provenance attestations. To verify a download:

    sha256sum -c SHA256SUMS
    gh attestation verify reportaudit-<version>.tar.gz --repo Tonsete/reportaudit-lab
