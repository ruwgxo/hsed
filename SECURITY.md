# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✓ Current |
| 0.2.x   | ✓         |
| < 0.2   | ✗         |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via GitHub's
[Security Advisories](https://github.com/ruwgxo/hsed/security/advisories/new)
feature, or email **hi@ruwgxo.com** with subject line `[hsed] Security Report`.

Include:
- hsed version (`pip show hsed`)
- Python version and OS
- A minimal reproducer or description of the issue
- Impact assessment if known

You will receive an acknowledgement within **3 business days** and a resolution
timeline within **7 business days**. Critical issues will be patched and
released on an accelerated schedule.

## Scope

In scope for this policy:

- Permission bypass — a role that should be denied being granted access
- Policy serialisation issues — loading a `.hsed` file triggers unintended behaviour
- Live auditor credential exposure — secrets leaked via logging or error messages
- Dependency vulnerabilities in optional extras (`boto3`, `azure-*`, `google-cloud-kms`)

Out of scope:

- Denial of service via crafted input
- Issues in caller code that uses hsed incorrectly
- Vulnerabilities in the cloud provider SDKs themselves (report directly to AWS / Azure / GCP)

## Disclosure Timeline

| Day | Action |
|-----|--------|
| 0   | Report received |
| 1–3 | Acknowledgement sent |
| 7   | Resolution timeline confirmed |
| TBD | Patch released + GitHub Advisory published |
| +7  | Public disclosure (coordinated with reporter) |

## Security Design Notes

hsed's core (`hsed`, `hsed.core`, `hsed.cli`) has **zero runtime dependencies**.
The permission model operates entirely in memory and never makes network calls.

Cloud connectivity is strictly opt-in via extras (`pip install hsed[aws]`,
`hsed[azure]`, `hsed[gcp]`). Credentials are never read, logged, or stored by
hsed — they are delegated entirely to the respective cloud SDK's standard
credential chain.

`.hsed` policy files are plain JSON and carry no executable content.
