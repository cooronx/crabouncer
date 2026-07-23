# crabouncer-sdk

`crabouncer-sdk` is the Rust client for Crabouncer's resource synchronization
extension. Use `authzen-rs` directly for standard AuthZEN Evaluation and Search;
this crate intentionally does not wrap those APIs.

```rust
use crabouncer_sdk::{Crabouncer, SyncOperation, SyncedResource};

let client = Crabouncer::new(
    "https://iam.example.com",
    service_client_id,
    service_client_secret,
)?;

let report = client
    .sync_resources([
        SyncOperation::upsert(
            SyncedResource::new("Document", document_id)
                .property("title", "Roadmap")
                .entity_property("owner", "User", owner_id),
        ),
        SyncOperation::delete("Document", removed_document_id),
    ])
    .await?;
```

The Service Account must have the `resources:sync` scope. The client caches its
Client Credentials token, refreshes it before expiry, and retries once after a
401 or a transient HTTP failure.

Each upsert is validated against the application's active Cedar schema.
`organization_id` is reserved and injected from the service token. Batch
responses may be partially successful; inspect `SyncReport::failures()`.

Call the SDK after the business transaction commits. Operations are idempotent,
but the client does not provide a database transaction or Outbox. Applications
that require guaranteed delivery should persist operations in their own
transactional Outbox and dispatch them with this client.
