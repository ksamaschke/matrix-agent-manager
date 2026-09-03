# Agent E2EE recovery

An agent that cannot decrypt incoming Matrix messages is usually holding a
stale device identity: its access token, MAS session, or local crypto state no
longer matches what the homeserver knows about its device. This guide describes
the server-side recovery action the Manager provides and the boundary it
deliberately does not cross.

## What the Manager does

`POST /api/agents/{name}/recover` (admin role, CSRF-protected; "Recover E2EE" in
the dashboard) runs one bounded server-side cycle:

1. **Rotate the MAS personal session.** The agent's previous session is
   invalidated and a replacement is issued with the same device-scoped token
   scope, so the new credential is bound to the same device ID.
2. **Persist the replacement.** The rotated token and the incremented
   generation are written to the agent's Secret in the configured secret
   backend. The response never contains token material.
3. **Check the device on the homeserver.** Using the freshly issued token, the
   Manager queries `/_matrix/client/v3/keys/query` for the agent's own user and
   reports whether the device ID is known to the homeserver and whether it
   publishes both its Ed25519 and Curve25519 identity keys.

The response reports `generation`, `status`, and a `device` object
(`device_id`, `known`, `keys_match`, `verified`). Rotation is durable even when
the follow-up device check fails — the check reports health, it does not gate
the rotation.

## What the Manager deliberately does not do

The Manager is a MAS/Matrix control plane. It does not connect to agent hosts,
does not write agent host configuration, and does not restart agent processes.
Megolm session keys and the agent's local crypto store live on the agent host
and are never transmitted to or through the Manager.

Consequently, **recovery is a two-party operation**:

| Side | Owner | Action |
|---|---|---|
| Server | Manager | Rotate MAS session, persist Secret, report device state |
| Host | Agent runtime | Consume the rotated Secret, restart the client, re-establish E2EE sessions |

The host side is intentionally out of scope. Deliver the rotated Secret to the
agent host through the mechanism that already governs that host (GitOps-managed
Secret sync, a host-side reconciler watching the Secret's `generation`, or your
existing configuration management). A host that keeps running with the previous
token will report `known: true, keys_match: true` while still failing to
decrypt, because its local crypto state was never refreshed.

## Interpreting the device report

| Result | Meaning | Next step |
|---|---|---|
| `known: false` | The homeserver has no such device for this agent | The agent host has never completed a login with this device ID; provision the host with the rotated credential |
| `known: true, keys_match: false` | Device exists but publishes no usable identity keys | The host's crypto store is stale or was reset without re-uploading keys; refresh the host's crypto state |
| `known: true, keys_match: true` | Server-side identity is healthy | Any remaining decryption failure is host-side: the agent still needs to pick up the rotated credential and restart |

`verified` reports cross-signing trust and is currently always `false`; the
Manager does not perform cross-signing on the agent's behalf.

## Configuration

Recovery requires the Client-Server API base URL of the homeserver:

```yaml
config:
  matrix:
    clientServerBaseURL: "https://matrix.example.invalid"
```

This maps to `AGENT_MANAGER_MATRIX_HOMESERVER_BASE_URL` and is validated as an
absolute HTTPS URL in production. Without it the Manager refuses to start.
