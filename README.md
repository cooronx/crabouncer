# Crabouncer

Crabouncer is a multi-tenant Rust IAM that connects OIDC identity, the OpenID
AuthZEN Authorization API 1.0, and Cedar policy evaluation. It includes an
administration web app and interoperates with the `authzen-rs` async Rust SDK.

## What is included

- OIDC Discovery, JWKS, Authorization Code + PKCE, UserInfo, rotating Refresh
  Tokens, and logout.
- OAuth Client Credentials through independently rotatable Service Account
  secrets.
- AuthZEN single and batch evaluations, including default inheritance and all
  three batch execution semantics.
- AuthZEN subject, resource, and action search with signed keyset pagination.
- Schema-validated synchronization of business resources for resource search.
- Application-scoped Cedar workspaces, validation, simulation, immutable
  releases, atomic publication, and rollback.
- Hard organization boundaries before Cedar evaluation. Every user belongs to
  exactly one organization; system administrators can manage every tenant.
- Decision logs with configurable field redaction and retention, plus
  management audit logs.
- React management UI and `authzen-rs` support for Rust PEP integrations.

## Run with Docker Compose

The default Compose configuration is for local development and is available at
<http://localhost:8080>.

```bash
CRABOUNCER_BOOTSTRAP_PASSWORD='replace-with-a-long-password' docker compose up --build
```

Log in as `admin@example.com`. RSA keys and PostgreSQL data are persisted in
named volumes. Changing or restarting containers does not invalidate existing
JWTs. Do not use the development HTTP URLs, database password, or fallback
bootstrap password in production.

To reset the local environment intentionally:

```bash
docker compose down --volumes
```

## Develop locally

Requirements: Rust 1.88+, PostgreSQL, Node 24+, pnpm, and OpenSSL.

```bash
cp config/app.example.toml config/app.toml
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out config/private.pem
openssl pkey -in config/private.pem -pubout -out config/public.pem
export CRABOUNCER_BOOTSTRAP_PASSWORD='replace-with-a-long-password'
cargo run -p crabouncer-core
```

In a second terminal:

```bash
cd web
pnpm install
pnpm dev
```

The Vite server proxies API, OAuth, AuthZEN, and discovery requests to port
3000. In production, deploy the Core and Web images separately behind one
hostname, as demonstrated by `compose.yaml` and `web/nginx.conf`.

## First end-to-end flow

1. Log in and create an organization. Copy the one-time Owner activation URL.
2. Activate the Owner, create an Application, and register its exact OIDC
   redirect URI.
3. Create a Service Account. Store the returned Client ID and Secret; the
   Secret is never displayed again.
4. Edit the Application workspace. Policies are represented as an array of
   `{ "name", "source", "enabled" }`; entities use Cedar's JSON entity format.
5. Validate and publish the workspace. Publication atomically activates an
   immutable release.
6. Use Authorization Code + PKCE for users and Client Credentials for the PEP.
   The service token audience is `authzen`; grant `authzen:evaluate` for
   AuthZEN calls and `resources:sync` for resource synchronization.
7. Call `POST /access/v1/evaluation` or `/access/v1/evaluations` and enforce the
   returned `decision`.

AuthZEN metadata is published at `/.well-known/authzen-configuration`. OIDC
metadata is published at `/.well-known/openid-configuration`.

## Rust clients

Use the published [`authzen-rs`](https://crates.io/crates/authzen-rs) crate for
the standard AuthZEN Evaluation and Search APIs. Crabouncer does not wrap or
duplicate its request and response types:

```toml
[dependencies]
authzen-rs = "0.2.1"
```

```rust
use authzen_rs::{Action, AuthZenClient, EvaluationRequest, Resource, Subject};

let authzen = AuthZenClient::builder("https://iam.example.com")
    .bearer_token(service_access_token)
    .discover()
    .build()
    .await?;

let decision = authzen
    .evaluate(EvaluationRequest::new(
        Subject::new("User", user_id),
        Action::new("factor.delete"),
        Resource::new("Factor", factor_id)
            .with_property("owner_id", user_id.to_string()),
    ))
    .await?;

if !decision.allowed() {
    // Reject the protected operation.
}
```

Obtain `service_access_token` from `/oauth2/token` with the Client Credentials
grant and the `authzen:evaluate` scope. `authzen-rs` accepts the resulting
Bearer Token; the calling service is responsible for token caching and refresh.

The workspace also contains `crabouncer-sdk`, a deliberately small client for
Crabouncer's resource synchronization extension:

```toml
[dependencies]
crabouncer-sdk = { path = "sdk" }
```

```rust
use crabouncer_sdk::{Crabouncer, SyncOperation, SyncedResource};

let crabouncer = Crabouncer::new(
    "https://iam.example.com",
    service_client_id,
    service_client_secret,
)?;

let report = crabouncer
    .sync_resources([
        SyncOperation::upsert(
            SyncedResource::new("Document", document_id)
                .property("title", "Roadmap")
                .entity_property("owner", "User", owner_id),
        ),
        SyncOperation::delete("Document", deleted_document_id),
    ])
    .await?;

for failure in report.failures() {
    eprintln!("resource sync failed at {}: {:?}", failure.index, failure.message);
}
```

Call synchronization after the business transaction commits. Upserts and
deletes are idempotent, batches return one result per operation, and the last
request received wins when multiple processes update the same resource. The
client obtains and caches a `resources:sync` service token. It does not include
an ORM integration, worker, or Outbox; applications that need guaranteed
delivery can place the same operations in their own transactional Outbox.

`organization_id` is reserved. Crabouncer derives it from the service token and
injects it before validating a synchronized resource against the active Cedar
schema. The same tenant attribute is injected when an Evaluation request omits
it; a conflicting caller-supplied value is denied.

The synchronization endpoint is `POST /resource-sync/v1/resources`. Search
endpoints are advertised through AuthZEN metadata and are available at:

```text
POST /access/v1/search/subject
POST /access/v1/search/resource
POST /access/v1/search/action
```

## Checks

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cd web && pnpm lint && pnpm build
```
