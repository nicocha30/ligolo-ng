# Security Policy

Ligolo-ng Relay is an operator-facing security tool. Treat findings in the
proxy, agent, relay protocol, API, release artifacts, and deployment manifests
as security-sensitive by default.

## Supported Versions

Security fixes are prepared for the latest published Ligolo-ng Relay release and
the current `master` branch. Older fork releases are not supported unless a
maintainer explicitly marks a backport branch as supported.

## Reporting A Vulnerability

Do not open a public issue for a suspected vulnerability.

Report privately through GitHub Security Advisories when available for this
repository. If advisories are unavailable, contact the maintainer at
`nicolas - at - chatelain.me` and include:

- affected version, commit, or container image digest
- affected component, such as proxy, agent, relay, API, Web UI, chart, or
  release artifact
- reproduction steps or proof of concept
- impact assessment and any known mitigations

If you need encrypted mail, ask for a PGP key before sending exploit details.

## Response Expectations

Maintainers should acknowledge actionable private reports within 5 business
days, validate severity, and coordinate a fix or mitigation before public
disclosure. Critical remote compromise or credential exposure reports should be
handled as release-blocking issues.

## Disclosure

When a fix is released, publish a concise advisory with affected versions,
impact, remediation steps, and credit if the reporter wants attribution. Avoid
including weaponized details until users have had a reasonable upgrade window.

## Release Security Gates

Do not publish a release unless the required checks in `doc/RELEASE.md` pass,
including Go tests, race tests, Web audit, `govulncheck`, scoped TLS-pinning
`gosec`, GoReleaser config validation, Helm template validation, and the relay
integration lab.
