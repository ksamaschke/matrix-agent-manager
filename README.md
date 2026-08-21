# Matrix Agent Manager

Matrix Agent Manager is an open-source control plane for centrally managing
Matrix-based agents. It is designed to provision agent identities through the
Matrix Authentication Service (MAS) Admin API and deliver credentials through a
separate secret backend.

The project is deployment-neutral. OIDC, MAS, Kubernetes, hostnames, namespaces,
roles, and secret backends are configured by the deployment environment.

## Status

The repository currently contains the security-conscious runtime foundation:

- typed environment configuration;
- fail-closed production validation;
- health/readiness endpoints;
- no production hostnames, credentials, or provider-specific routes.

Agent lifecycle APIs, the operator, and the UI are planned and will be added
behind tests and independent security review.

## Local development

Requirements: Go 1.23 or newer.

```bash
go test ./...
go run ./cmd/agent-manager
curl http://127.0.0.1:8080/healthz
```

Production configuration requires all trust boundaries to be explicit:

```text
AGENT_MANAGER_ENV=production
AGENT_MANAGER_OIDC_ISSUER_URL=https://idp.example.invalid/realms/example
AGENT_MANAGER_OIDC_CLIENT_ID=agent-manager
AGENT_MANAGER_OIDC_AUDIENCE=agent-manager
AGENT_MANAGER_MAS_BASE_URL=https://mas.example.invalid
AGENT_MANAGER_MAS_TOKEN_URL=https://mas.example.invalid/oauth2/token
AGENT_MANAGER_MAS_USERS_URL=https://mas.example.invalid/api/admin/v1/users
AGENT_MANAGER_MAS_PERSONAL_SESSIONS_URL=https://mas.example.invalid/api/admin/v1/personal-sessions
AGENT_MANAGER_MAS_CLIENT_ID=agent-manager-admin
AGENT_MANAGER_MAS_CLIENT_SECRET_FILE=/var/run/secrets/mas/client-secret
AGENT_MANAGER_SECRET_BACKEND=kubernetes
AGENT_MANAGER_SECRET_NAMESPACE=agent-manager
```

Do not place secret values in environment variables, source code, Helm values,
CRD status, logs, or Git. Use mounted files or a supported secret backend.

## License

Apache-2.0. See [LICENSE](LICENSE).
