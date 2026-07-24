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
- Organization-scoped Physical and Virtual Groups with a single-Physical-Group
  constraint per user.
- Application-scoped Roles assignable directly to users or through Groups,
  with authoritative effective-role resolution during authorization.
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
4. If the Application uses Roles, create the Groups and Application Roles that
   its policies will reference.
5. Edit the Application workspace. Policies are represented as an array of
   `{ "name", "source", "enabled" }`; entities use Cedar's JSON entity format.
   Include the managed IAM schema contract when using Groups or Roles.
6. Validate and publish the workspace. Publication atomically activates an
   immutable release.
7. Assign Application Roles directly to users or through Groups.
8. Use Authorization Code + PKCE for users and Client Credentials for the PEP.
   The service token audience is `authzen`; grant `authzen:evaluate` for
   AuthZEN calls and `resources:sync` for resource synchronization.
9. Call `POST /access/v1/evaluation` or `/access/v1/evaluations` and enforce the
   returned `decision`.

AuthZEN metadata is published at `/.well-known/authzen-configuration`. OIDC
metadata is published at `/.well-known/openid-configuration`.

## Groups and Application Roles

Groups are scoped to an Organization and are manually maintained. A user can
belong to at most one Physical Group and any number of Virtual Groups. Groups
cannot be nested. Application Roles are scoped to one Application and can be
assigned to a user or to a Group from the same Organization.

Both resources have an immutable lowercase `key`, a mutable display name, and
an enabled state. They are disabled instead of deleted so that identifiers and
relationships are retained. Disabled Groups and Roles do not contribute to
authorization.

The management endpoints are:

```text
GET|POST /api/v1/organizations/{organization_id}/groups
GET|PATCH /api/v1/groups/{group_id}
GET       /api/v1/groups/{group_id}/members
PUT|DELETE /api/v1/groups/{group_id}/members/{user_id}
GET       /api/v1/users/{user_id}/groups

GET|POST /api/v1/applications/{application_id}/roles
GET|PATCH /api/v1/application-roles/{role_id}
GET       /api/v1/application-roles/{role_id}/assignments
PUT|DELETE /api/v1/application-roles/{role_id}/users/{user_id}
PUT|DELETE /api/v1/application-roles/{role_id}/groups/{group_id}
GET       /api/v1/applications/{application_id}/users/{user_id}/effective-roles
```

`Owner`, `Admin`, and system administrators can mutate these resources.
Organization `Member`s can read them, but may only inspect their own effective
Roles. Organization Roles control Crabouncer administration only; they never
implicitly grant an Application Role.

The root Cedar types `User`, `Group`, and `Role` are managed by Crabouncer.
They cannot be supplied as workspace entities, synchronized resources, or
AuthZEN business resources. Namespaced types such as `Example::Role` remain
available to applications. A Role-enabled schema must provide this contract:

```text
User
  memberOfTypes: Group, Role
  required String attributes: organization_id, email, role

Group
  memberOfTypes: Role
  required String attributes: organization_id, kind

Role
  required String attributes: organization_id, application_id
```

Optional custom attributes are allowed, but additional required attributes on
these managed types are not. Publishing or activating a policy that references
`Group::"<key>"` or `Role::"<key>"` validates that the referenced object
exists. Creating an assignment requires an active release that satisfies the
full contract.

Crabouncer reads enabled Group and Role relationships from PostgreSQL for each
Evaluation or Search operation and builds the Cedar membership graph:

```text
User parents  = Groups + directly assigned Roles
Group parents = Roles assigned to that Group
Role parents  = none
```

Application Roles are deliberately absent from user access tokens, so an
assignment change takes effect on the next authorization operation. Evaluation
decision logs include the compact Group and effective-Role snapshot used for
the decision. Management UI for Groups and Application Roles is not included
yet; use the APIs above.

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
