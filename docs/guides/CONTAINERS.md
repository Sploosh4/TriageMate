# Container operation

TriageMate runs with exactly two Compose services. `app` contains FastAPI, compiled React and the input/operations code. `db` runs PostgreSQL 16. Default access is [http://127.0.0.1:5190](http://127.0.0.1:5190); PostgreSQL has no published host port.

## Setup

Use Docker Desktop in Linux-container mode on Windows, or Docker Engine with Compose v2 elsewhere. From the root on Windows:

```powershell
scripts\setup-containers.cmd
```

The helper preserves existing `.env` and creates it when absent. Manual setup copies `.env.example` to `.env`, sets a unique random `TRIAGEMATE_DB_OWNER_PASSWORD` of at least 32 characters and optionally sets `TRIAGEMATE_PORT` (default `5190`). Keep `.env` private. Then run:

```sh
docker compose up -d --build --wait
docker compose ps
```

Identify a conflicting port owner before stopping it or choosing another port. Verify Compose's intended container address and `/api/health`; a stale native service is not container acceptance. Never stop unrelated processes to free a port.

Initial builds obtain pinned images, locked Python/Node dependencies and verified SQL-parser source. Bootstrap provisions fresh databases through the retained lifecycle and verifies supported installations. It does not silently adopt arbitrary databases or weaken grants. Editing `.env` does not rotate an initialized PostgreSQL password; database and application credentials must be reconciled explicitly.

## Storage and restart

The `database` named volume stores PostgreSQL data. The `application` volume stores configuration/credentials, durable operation state and input bundles. Compose normally names them `triagemate_database` and `triagemate_application`. Container recreation and image rebuild preserve both.

```sh
docker compose logs --tail=100 app db
docker compose stop
docker compose up -d --wait
docker compose restart app
```

`docker compose down` preserves volumes. **`docker compose down -v` destroys retained evidence and configuration in both volumes.** Do not use it for routine troubleshooting or upgrades. Avoid pruning volumes holding evidence. Restart is configured as `unless-stopped`.

A named volume survives container recreation, but is not a backup and cannot protect against disk loss. Keep data and recovery secrets in separate private backup storage.

## Backup and restore

Stop application writers before a coordinated database/state backup. Use PostgreSQL logical dump tooling inside `db`, copy output to a private location and preserve matching application-volume state and deployment configuration. Dumps may contain private evidence; do not commit or upload them as fixtures. Avoid PowerShell text redirection for binary/custom-format dumps.

Restore first into an isolated temporary target. Verify schema/authority signatures, representative evidence and restricted-reader access. Restore application state only with matching database/configuration identities. Overwriting current volumes needs tested recovery and explicit destructive-operation authorization. Native installations require explicit export and verified transition; Compose never mounts old database directories automatically.

## Network and inputs

The host port binds to IPv4 loopback. The app listens on port 8000 inside its container, with Compose controlling host exposure. Do not change the host mapping to `0.0.0.0` as a routine setup fix.

This first refactor targets one local user. Request-origin/session guards are not identity authentication. External access needs agreed authentication, authorization, TLS and operational tests. Licensing does not authorize repository publication or disclosure of private data.

Source registration does not enable Microsoft collection. Supply authorized credentials/configuration privately; deferred sources remain inactive unless explicitly selected and supported. Windows registry/Appx inventory needs an authorized source-side export; Linux containers cannot inspect a remote machine's registry automatically.
