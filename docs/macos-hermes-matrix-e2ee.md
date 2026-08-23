# Hermes Agent on macOS with Matrix E2EE

This is a practical deployment note for running the [Hermes Agent](https://github.com/NousResearch/hermes-agent) Matrix gateway from macOS, including encrypted Matrix rooms.

It is intentionally a **guide, not a fork or patched source distribution**. The native macOS build issue described below belongs upstream; keeping a local patch would create an ongoing maintenance obligation.

## What you need

- A working Hermes Agent installation and configured model/provider.
- A dedicated Matrix bot account on your homeserver (a separate account is recommended).
- A Matrix access token for that account, or its user ID and password.
- A private test room where the bot can be invited.
- For E2EE, the Matrix Python dependencies and the `libolm` crypto library.

Hermes supports homeservers such as Synapse, Dendrite, Conduit, and matrix.org. Keep the Matrix bot account separate from your personal account so credentials, device state, and recovery can be rotated independently.

## Important Apple Silicon caveat

Hermes uses `mautrix` with the `python-olm` bindings for Matrix encryption. At the time of writing, `python-olm` does not provide a usable macOS ARM64 wheel. Installing the Hermes Matrix extra can therefore try to compile libolm locally. On current Apple clang versions, that build may fail in libolm's bundled source with a const-correctness error in `include/olm/list.hh`.

This means that `brew install libolm` alone is **not sufficient**: `python-olm` still builds its own bundled libolm when installed from PyPI.

### Recommended macOS deployment: Linux container for the Matrix adapter

Use Hermes' proxy mode:

- **macOS host:** runs the main Hermes agent, tools, skills, sessions, memory, and local-file access.
- **Linux container:** runs only the Matrix adapter and E2EE crypto.
- The container forwards decrypted messages to the host API server and encrypts responses before sending them to Matrix.

This avoids distributing or maintaining a patched `python-olm` source tree.

## Host setup (macOS)

Configure the host Hermes instance in `~/.hermes/.env`:

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

From the container, the macOS host is normally reachable as `host.docker.internal` with Docker Desktop. If using another VM/runtime, use the host address reachable from that VM instead.

Do not expose port 8642 to the public Internet. Restrict it to the local Docker/VM network and protect it with a strong `API_SERVER_KEY`.

## Matrix adapter container

The container needs the Matrix credentials and proxy settings, but it does **not** need an LLM API key because inference remains on the macOS host.

Example `docker-compose.yml`:

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

Example `Dockerfile`:

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

The exact image installation should follow the Hermes release you are using; do not blindly copy a development checkout into production. Pin the Hermes version and rebuild the image when upgrading.

Start the adapter after the host is running:

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

## Native installation: why this guide does not provide a patch

A native install may be possible by patching the bundled libolm source and building a local `python-olm` wheel. That is not a stable distribution strategy:

- the patch is outside the normal PyPI package;
- the build may change with Python, clang, libolm, or Hermes versions;
- every Hermes upgrade would need retesting;
- distributing a private wheel creates a support and security-maintenance burden.

For repeatable deployments, prefer the Linux-container proxy path until upstream provides a supported macOS ARM64 build or changes the Matrix crypto dependency.

## Troubleshooting checklist

1. Check that the host gateway is running and port 8642 is reachable from the container.
2. Verify that `GATEWAY_PROXY_KEY` exactly matches `API_SERVER_KEY`.
3. Check the container logs for Matrix sync and crypto initialization errors.
4. Confirm the bot is invited to the room and that the room is in `MATRIX_ALLOWED_ROOMS`.
5. Confirm the sender is in `MATRIX_ALLOWED_USERS`.
6. Preserve the Matrix crypto store across restarts.
7. If E2EE is required, do not silently change to `optional` or `off` to hide a crypto failure.

## References

- [Hermes Matrix documentation](https://hermes-agent.nousresearch.com/docs/user-guide/messaging/matrix)
- [Hermes Agent repository](https://github.com/NousResearch/hermes-agent)
- [mautrix Python SDK](https://github.com/mautrix/python)
- [python-olm](https://gitlab.matrix.org/matrix-org/python-olm)
