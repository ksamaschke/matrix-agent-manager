# Security Policy

## Scope

Matrix Agent Manager handles administrative Matrix operations and one-time agent
access tokens. Treat all releases and deployments as security-sensitive.

## Reporting

Please report vulnerabilities privately through the repository's GitHub security
advisory mechanism. Do not publish credentials, tokens, or exploit details in a
public issue.

## Security invariants

- No production configuration is compiled into the binary.
- OIDC issuer, audience, redirect origins, MAS URL, and secret backend are
  explicit deployment inputs.
- MAS admin credentials never reach the browser.
- Agent tokens are returned only at creation/rotation time and are never logged
  or returned by ordinary reads.
- Authorization is enforced server-side; UI visibility is not authorization.
- Production startup fails closed when trust-boundary configuration is missing.
- The public product repository contains no real credentials or private hostnames.

Security review is required before enabling mutating APIs or publishing a
production deployment chart.
