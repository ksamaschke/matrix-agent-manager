# Matrix E2EE Recovery Lifecycle Implementation Plan

> **For HEX:** Execute this plan task-by-task with the subagent-driven-development workflow and verify the live encrypted-room path before claiming completion.

**Goal:** Give Manager-provisioned Matrix agents a separate, secure E2EE recovery-key lifecycle for the central Linux Hermes transport without exposing recovery material through the dashboard, ordinary APIs, logs, or Git.

**Architecture:** The Manager owns a separate per-agent Kubernetes E2EE Secret and reports only status/device metadata. The central Linux Hermes transport owns `mautrix`/`libolm`, a persistent crypto store, and the initial cross-signing bootstrap; a narrow Kubernetes sidecar publishes the generated recovery key once into the E2EE Secret. Mac Hermes runtimes use authenticated API-server/proxy mode and do not handle Matrix room keys.

**Tech Stack:** Go, Kubernetes Secrets/RBAC, Helm/ArgoCD, Hermes Docker image, `mautrix`/`libolm`, persistent volume.

---

## Context and relevant files

- Product: `/Users/karsten/matrix-agent-manager`
  - `internal/agents/service.go`: MAS lifecycle and token contract.
  - `internal/agents/kubernetes.go`: current token/metadata Secret backend.
  - `internal/httpapi/server.go`: authenticated Manager API/UI.
  - `cmd/agent-manager/main.go`: service wiring.
  - `internal/config/config.go`: deployment-neutral configuration.
  - `helm/matrix-agent-manager/*`: product chart and RBAC.
- Infrastructure: `/tmp/infrastructure`
  - `kubernetes/gitops/matrix-agent-manager/*`: Manager deployment.
  - `kubernetes/gitops/matrix/*`: Synapse/MAS and Matrix routing.
- Hermes runtime:
  - `~/.hermes/hermes-agent/plugins/platforms/matrix/adapter.py`: E2EE bootstrap, recovery-key import, crypto store.
  - `~/.hermes/hermes-agent/website/docs/user-guide/messaging/matrix.md`: supported proxy-mode architecture.

## Current verified state

- Manager Secret `matrix-agents/matrix-agent-hex-work` contains access-token/session and identity metadata, but no recovery key.
- Hermes Matrix config has E2EE required, but the macOS environment lacks `mautrix` encryption dependencies and `libolm`; the gateway refuses to connect rather than silently downgrade.
- Synapse/MAS are healthy; `mas-synapse-secret` is unrelated to the Hermes E2EE recovery key.
- Hermes Docker image includes Linux `libolm` and the Matrix encryption extra.
- Hermes proxy mode already forwards decrypted Matrix text to a remote Mac API server and encrypts the streamed response on the transport side.

## Non-goals and invariants

- Do not derive or fabricate a Matrix recovery key from an MAS token.
- Do not place recovery keys in the existing token Secret or one-time token API response.
- Do not write recovery keys to Git, Helm values, logs, process arguments, or ordinary dashboard HTML.
- Do not share Matrix tokens, device IDs, crypto stores, or recovery keys between independent agents.
- Do not delete or replace a non-empty recovery key implicitly during ordinary token rotation.
- Preserve the existing device-scoped MAS token contract and Manager remove/deactivate semantics.
- The crypto store remains mandatory; the recovery key is not a substitute for persisted Olm state.

## Implementation sequence

### Task 1: Add the separate E2EE Secret contract

Files:
- Modify `internal/agents/service.go`.
- Modify `internal/agents/kubernetes.go`.
- Modify `internal/agents/service_test.go` and `internal/agents/kubernetes_test.go`.

Add a separate `E2EERecord`/`E2EEBackend` contract with:
- agent name;
- expected device ID;
- status (`pending`, `ready`, `degraded`);
- recovery-key bytes held only by the backend/transport path;
- resource version and timestamps.

Use a distinct Secret name/type/labels and a separate CAS update path. Ordinary agent metadata/list/detail results expose only E2EE status and device ID, never recovery-key bytes.

Acceptance:
- Existing token Secret serialization is unchanged.
- E2EE Secret round-trips through the Kubernetes fake backend.
- Empty/pending and ready records validate correctly.
- Recovery key is absent from JSON metadata and ordinary list results.

### Task 2: Wire Manager lifecycle and status

Files:
- Modify `internal/agents/service.go` and service tests.
- Modify `internal/httpapi/server.go` and HTTP tests.
- Modify `cmd/agent-manager/main.go` and config tests.
- Modify chart values/schema/configmap as needed.

When E2EE management is enabled:
- Create/ensure a pending E2EE record after successful agent provisioning.
- Keep the E2EE record during rotate/revoke.
- Delete it only after successful permanent remove/deactivation cleanup.
- Return `e2ee_status` and `e2ee_device_id` only.
- Add an admin-only idempotent initialization/status endpoint for existing managed agents so `hex-work` can receive its pending E2EE Secret without manually writing one.

Acceptance:
- Create, rotate, revoke, deactivate, remove, and rollback paths preserve/delete E2EE state correctly.
- Existing `hex-work` can be initialized without exposing token or recovery material.
- CSRF/admin boundaries cover the new endpoint.

### Task 3: Add central Linux Hermes transport for HEX

Files:
- Add GitOps resources under `/tmp/infrastructure/kubernetes/gitops/matrix-hermes-transport/`.
- Add an ArgoCD Application and immutable Hermes image digest.
- Add a persistent PVC for `/opt/data` and a per-agent transport Secret contract.
- Add ServiceAccount/Role/RoleBinding limited to the HEX E2EE Secret.
- Add a recovery-key publisher sidecar that reads the one-time Hermes output file, patches only the recovery-key/status fields, never logs the value, and removes the temporary file after verified write-back.

Transport configuration:
- `MATRIX_E2EE_MODE=required`;
- `MATRIX_DEVICE_ID=agent-hex-work`;
- `MATRIX_RECOVERY_KEY` from the separate E2EE Secret, optional only for first bootstrap;
- `MATRIX_RECOVERY_KEY_OUTPUT_FILE` on the persistent bootstrap path;
- `MATRIX_ACCESS_TOKEN` from the Manager token Secret;
- `GATEWAY_PROXY_URL` to the Mac API server;
- per-transport `GATEWAY_PROXY_KEY` from Kubernetes Secret.

Acceptance:
- Linux transport starts with `libolm`/mautrix available.
- E2EE crypto store persists across pod restart.
- Recovery key is published once and never appears in logs/events.
- A restart consumes the stored recovery key and reports cross-signing verification.

### Task 4: Configure Mac proxy endpoint

Files:
- Update the local Hermes `.env` only through a mode-0600 atomic write; never commit it.
- Disable the local Matrix adapter after central transport acceptance.
- Enable authenticated API server on a private/VPN-reachable interface.

Acceptance:
- Mac API server returns authenticated `/health` and `/v1/chat/completions`.
- Central transport can reach it through the private path.
- API key differs from Matrix/MAS credentials and is not logged.

### Task 5: Gates and live acceptance

Product gates:
- `gofmt`, `go test ./... -count=1`, `go test -race ./...`, `go vet ./...`, source hygiene, Helm lint/template, `git diff --check`.

Infrastructure gates:
- rendered manifests contain no secret values;
- ArgoCD `Synced/Healthy/Succeeded`;
- pods/PVC/Secret mounts ready;
- no recovery-key material in logs/events.

User-facing acceptance:
1. Create or initialize the HEX E2EE state.
2. Verify central transport syncs as `@agent:example.invalid` with its configured device ID.
3. Use a fresh private encrypted Matrix room.
4. Send a message from Element; verify Hermes decrypts and replies encrypted.
5. Verify the reply is readable in Element and the transport survives restart.
6. Verify Manager rotation does not destroy the crypto store or recovery Secret.

## Security review focus

- Recovery-key write path is authenticated and resource-scoped.
- Kubernetes Role cannot read unrelated agent token Secrets.
- E2EE Secret is not included in Manager one-time token responses.
- API/proxy link uses per-agent bearer credentials over a private route; plaintext exists only across that controlled link.
- Backup/restore includes the crypto PVC and E2EE Secret as separate protected assets.
- Token rotation and device identity remain consistent; stale device/crypto-store mismatches fail closed.
