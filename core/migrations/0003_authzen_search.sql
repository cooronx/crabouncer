CREATE TABLE search_logs (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    service_account_id uuid NOT NULL REFERENCES service_accounts(id) ON DELETE RESTRICT,
    request_id text NOT NULL,
    search_kind text NOT NULL,
    query jsonb NOT NULL,
    release_id uuid REFERENCES policy_releases(id) ON DELETE RESTRICT,
    evaluated_count integer NOT NULL,
    result_count integer NOT NULL,
    result_ids jsonb NOT NULL DEFAULT '[]',
    duration_us bigint NOT NULL,
    outcome text NOT NULL,
    error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (search_kind IN ('subject', 'resource', 'action')),
    CHECK (outcome IN ('success', 'error')),
    CHECK (evaluated_count >= 0),
    CHECK (result_count >= 0)
);
CREATE INDEX search_logs_tenant_created
    ON search_logs(organization_id, created_at DESC);
CREATE INDEX search_logs_expiry ON search_logs(created_at);
