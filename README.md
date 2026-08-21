# Matrix Agent Manager

Matrix Agent Manager is an open-source control plane for centrally managing
Matrix-based agents. It is designed to provision agent identities through the
Matrix Authentication Service (MAS) Admin API and deliver credentials through a
separate secret backend.

The project is deployment-neutral. OIDC, MAS, Kubernetes, hostnames, namespaces,
roles, and secret backends are configured by the deployment environment.

## Status

The repository contains a tested API/UI MVP for administrative Matrix agent
lifecycle management:

- generic OIDC login with PKCE, state, nonce, issuer, audience, signature, and
  role validation;
- CSRF-protected browser mutations;
- named agent creation and metadata-only listing;
- one-time token delivery on creation and rotation;
- token rotation, explicit revocation, deactivation, and removal;
- MAS user/session cleanup with bounded active-session enumeration;
- Kubernetes Secret persistence with namespace-scoped RBAC;
- fail-closed production configuration and an immutable-container Helm chart.

The product remains deployment-neutral. Hostnames, Keycloak details, MAS
endpoints, namespaces, and Secret references belong in deployment overlays.
The optional operator/CRD is not part of this API-based MVP.

## Local development

The production binary intentionally refuses to start with development defaults.
Use the unit/race tests for local development; run the server only with a
complete production-style environment and mounted Secret files.

```bash
go test ./...
go test -race ./...
```

Production configuration requires all trust boundaries to be explicit:

```text
AGENT_MANAGER_ENV=production
AGENT_MANAGER_OIDC_ISSUER_URL=https://idp.example.invalid/realms/example
AGENT_MANAGER_OIDC_CLIENT_ID=agent-manager
AGENT_MANAGER_OIDC_AUDIENCE=agent-manager
AGENT_MANAGER_OIDC_CLIENT_SECRET_FILE=/var/run/secrets/matrix-agent-manager/oidc/client-secret
AGENT_MANAGER_OIDC_REDIRECT_URL=https://app.example.invalid/auth/callback
AGENT_MANAGER_OIDC_ROLES_CLAIM=roles
AGENT_MANAGER_OIDC_REQUIRED_ROLES=matrix-agent-admin,matrix-agent-viewer
AGENT_MANAGER_COOKIE_SECURE=true
AGENT_MANAGER_SESSION_KEY_FILE=/var/run/secrets/matrix-agent-manager/session/session-key
AGENT_MANAGER_MAS_BASE_URL=https://mas.example.invalid
AGENT_MANAGER_MAS_TOKEN_URL=https://mas.example.invalid/oauth2/token
AGENT_MANAGER_MAS_USERS_URL=https://mas.example.invalid/api/admin/v1/users
AGENT_MANAGER_MAS_PERSONAL_SESSIONS_URL=https://mas.example.invalid/api/admin/v1/personal-sessions
AGENT_MANAGER_MAS_CLIENT_ID=agent-manager-admin
AGENT_MANAGER_MAS_CLIENT_SECRET_FILE=/var/run/secrets/matrix-agent-manager/mas/client-secret
AGENT_MANAGER_SECRET_BACKEND=kubernetes
AGENT_MANAGER_SECRET_NAMESPACE=agent-manager
```

Do not place secret values in environment variables, source code, Helm values,
CRD status, logs, or Git. Use mounted files or a supported secret backend.

## License

Apache-2.0. See [LICENSE](LICENSE).
