# Crabouncer Core

Rust HTTP API for the first Crabouncer IAM release. This release includes global
users, organizations and memberships, server-side sessions, applications,
application roles, and Cedar schema/policy management.

OIDC, the authorization decision endpoint, audit logging, and the frontend are
outside this release.

## Run locally

Create a PostgreSQL database, copy `config/app.example.toml` to
`config/app.toml`, then update the local configuration:

```toml
[server]
bind = "127.0.0.1:3000"

[database]
url = "postgres://postgres:postgres@localhost/crabouncer"

[bootstrap]
password = "123456"

[session]
cookie_secure = false
ttl_seconds = 28800
```

Then run from the repository root:

```text
cargo run -p crabouncer-core
```

Migrations run automatically. On the first startup, Crabouncer creates the
immutable `system` organization and the global `crabouncer` administrator. Its
password comes from `bootstrap.password`. The administrator must change this
password before using management endpoints.

Production deployments should replace the bootstrap password, enable
`session.cookie_secure`, and terminate traffic over HTTPS.

By default the server reads `config/app.toml` relative to its working directory.
Set `CRABOUNCER_CONFIG` only when a deployment needs to load a different path.

## Session authentication

Log in with `POST /api/v1/session` and a JSON body containing `username` and
`password`. The response sets an HttpOnly Session Cookie and returns a CSRF
token. Send that token in `X-CSRF-Token` for every state-changing request.

Errors use `application/problem+json` with `title`, `status`, `detail`, and a
stable `code`. Validation failures can also include an `errors` array.

Cedar schemas are accepted in Cedar's JSON schema format. Policy source uses
the Cedar policy language. Policies are edited as drafts and only affect the
published copy after the publish endpoint validates them against the current
schema.
