# Hermes Agent on macOS with Matrix E2EE

Practical notes for running the [Hermes Agent](https://github.com/NousResearch/hermes-agent) Matrix gateway from macOS, including encrypted Matrix rooms.

This documents the **native fix that was actually implemented and verified on Apple Silicon**, plus the documented proxy-mode alternative. It is a guide, not a fork or a maintained patched-source distribution.

## What you need

- A working Hermes Agent installation and configured model/provider.
- A dedicated Matrix bot account on your homeserver (a separate account is recommended).
- A Matrix access token for that account, or its user ID and password.
- A private test room where the bot can be invited.
- For E2EE, the Matrix Python dependencies and the `libolm` crypto library.

Hermes supports homeservers such as Synapse, Dendrite, Conduit, and matrix.org. Keep the Matrix bot account separate from your personal account so credentials, device state, and recovery can be rotated independently.

## The Apple Silicon problem

Hermes uses `mautrix` with the `python-olm` bindings for Matrix encryption. Two things are true on macOS ARM64:

1. **`python-olm` ships no macOS ARM64 wheel.** Every version is source-only on this platform, so installing it triggers a local compile.
2. **The bundled libolm source fails to compile on current Apple clang.** The build dies in `libolm/include/olm/list.hh` with a const-correctness error:

   ```
   include/olm/list.hh:106:13: error: cannot assign to variable 'other_pos'
   include/olm/list.hh:102:19: note: variable 'other_pos' declared const
   ```

   Line 102 declares `other_pos` as `T * const` (a const pointer) but line 106 increments it. Modern clang rejects this.

`brew install libolm` alone is **not sufficient**: `python-olm` builds its own bundled libolm from source when installed from PyPI, so the system libolm is never used.

## Native fix (what we actually did)

The failing line is a one-character bug. Removing the `const` from the pointer declaration makes the bundled libolm compile, and a native macOS ARM64 wheel can then be built and installed. This keeps E2EE running natively on the Mac — no Docker, no proxy.

### 1. Get the `python-olm` source

```bash
cd /tmp
curl -sL "https://pypi.org/simple/python-olm/" \
  -H "Accept: application/vnd.pypi.simple.v1+json" -o olm_index.json
# Grab the 3.2.16 sdist URL from olm_index.json, then:
curl -sL "<sdist-url>" -o olm.tar.gz
tar xzf olm.tar.gz -C /tmp
```

### 2. Patch the bundled libolm

Edit `/tmp/python-olm-3.2.16/libolm/include/olm/list.hh`:

```diff
         T * this_pos = _data;
-        T * const other_pos = other._data;
+        T * other_pos = other._data;
         while (other_pos != other._end) {
```

### 3. Build a native wheel

```bash
cd /tmp/python-olm-3.2.16
~/.hermes/hermes-agent/venv/bin/pip wheel . --no-deps -w /tmp/olm_wheels
```

This produces `python_olm-3.2.16-cp311-cp311-macosx_11_0_arm64.whl`.

### 4. Install the wheel, then the Hermes Matrix extra

```bash
cd ~/.hermes/hermes-agent
uv pip install --python venv/bin/python /tmp/olm_wheels/python_olm-3.2.16-*.whl
uv pip install --python venv/bin/python --find-links /tmp/olm_wheels -e ".[matrix]"
```

The `--find-links` points the resolver at the local wheel so it does not try to rebuild `python-olm` from source.

### 5. Verify

```bash
venv/bin/python -c "import olm; from olm import Account; a=Account(); print(list(a.identity_keys.keys()))"
# expect: ['curve25519', 'ed25519']

venv/bin/python -c "import sys; sys.path.insert(0,'.'); from tools.lazy_deps import is_available; print(is_available('platform.matrix'))"
# expect: True
```

### Maintenance caveat

This is a **local workaround**, not a supported distribution. The patch lives outside the normal PyPI package, so:

- every Hermes upgrade that reinstalls `python-olm` needs the wheel rebuilt;
- the build may change with Python, clang, libolm, or Hermes versions;
- do not publish the private wheel or treat it as a maintained artifact.

If you want a repeatable, no-patch deployment, use the proxy-mode path below instead.

## Alternative: proxy mode (Linux container for the Matrix adapter)

If you prefer not to patch anything, run only the Matrix adapter (with E2EE) in a Linux container and let it forward to the native macOS agent:

- **macOS host:** runs the main Hermes agent, tools, skills, sessions, memory, and local-file access.
- **Linux container:** runs only the Matrix adapter and E2EE crypto.
- The container forwards decrypted messages to the host API server and encrypts responses before sending them to Matrix.

### Host setup (macOS)

In `~/.hermes/.env`:

```dotenv
API_SERVER_ENABLED=true
API_SERVER_HOST=0.0.0.0
API_SERVER_PORT=8642
API_SERVER_KEY=generate-a-long-random-secret
```

Start the host gateway:

```bash
hermes gateway
```

From the container, the macOS host is normally reachable as `host.docker.internal` with Docker Desktop. Do not expose port 8642 to the public Internet; restrict it to the local Docker/VM network and protect it with a strong `API_SERVER_KEY`.

### Matrix adapter container

The container needs the Matrix credentials and proxy settings, but **not** an LLM API key (inference stays on the macOS host).

`docker-compose.yml`:

```yaml
services:
  hermes-matrix:
    build: .
    environment:
      MATRIX_HOMESERVER: "https://matrix.example.org"
      MATRIX_ACCESS_TOKEN: "syt_replace_me"
      MATRIX_ALLOWED_USERS: "@you:matrix.example.org"
      MATRIX_E2EE_MODE: "required"
      MATRIX_DEVICE_ID: "HERMES_MACOS_MATRIX"
      GATEWAY_PROXY_URL: "http://host.docker.internal:8642"
      GATEWAY_PROXY_KEY: "same-value-as-API_SERVER_KEY"
    volumes:
      - ./matrix-store:/root/.hermes/platforms/matrix/store
```

`Dockerfile`:

```dockerfile
FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libolm-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Hermes in the image using the release/source-install method
# appropriate for your Hermes version, including its Matrix extra.
# Example for a checked-out Hermes source tree:
# COPY hermes-agent /opt/hermes-agent
# RUN pip install -e '/opt/hermes-agent[matrix]'

CMD ["hermes", "gateway"]
```

Pin the Hermes version and rebuild the image when upgrading. Start the adapter after the host is running:

```bash
docker compose up -d
```

Then invite the bot to a private encrypted room and send a test message.

## Credentials and security

Use a dedicated bot account and restrict both users and rooms:

```dotenv
MATRIX_ALLOWED_USERS=@you:matrix.example.org
MATRIX_ALLOWED_ROOMS=!private-room-id:matrix.example.org
```

Without these restrictions, any user who can reach a joined room may be able to trigger an agent turn with Hermes' full tool access.

Treat the Matrix access token, API server key, and Matrix recovery key like passwords. Do not commit them, place them in a public issue, or include them in logs.

## E2EE configuration

Use fail-closed mode when encrypted rooms are required:

```dotenv
MATRIX_E2EE_MODE=required
```

Hermes stores Matrix crypto state under:

```text
~/.hermes/platforms/matrix/store/
```

Persist the container's corresponding `matrix-store` volume. Deleting `crypto.db` destroys the bot device's local encryption identity and can require device/token recovery.

If using cross-signing, configure the bot's Matrix recovery/security key according to the Hermes Matrix documentation. Keep the recovery key outside Git and ordinary logs.

## Troubleshooting checklist

1. Confirm `python-olm` imports and creates an Olm account (native path) before configuring the gateway.
2. Check that the host gateway is running and port 8642 is reachable from the container (proxy path).
3. Verify that `GATEWAY_PROXY_KEY` exactly matches `API_SERVER_KEY` (proxy path).
4. Check the gateway/container logs for Matrix sync and crypto initialization errors.
5. Confirm the bot is invited to the room and that the room is in `MATRIX_ALLOWED_ROOMS`.
6. Confirm the sender is in `MATRIX_ALLOWED_USERS`.
7. Preserve the Matrix crypto store across restarts.
8. If E2EE is required, do not silently change to `optional` or `off` to hide a crypto failure.

## References

- [Hermes Matrix documentation](https://hermes-agent.nousresearch.com/docs/user-guide/messaging/matrix)
- [Hermes Agent repository](https://github.com/NousResearch/hermes-agent)
- [mautrix Python SDK](https://github.com/mautrix/python)
- [python-olm](https://gitlab.matrix.org/matrix-org/python-olm)