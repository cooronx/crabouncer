CREATE TABLE application_resources (
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    resource_type text NOT NULL CHECK (resource_type = btrim(resource_type) AND resource_type <> ''),
    resource_id text NOT NULL CHECK (resource_id = btrim(resource_id) AND resource_id <> ''),
    properties jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (application_id, resource_type, resource_id),
    CHECK (jsonb_typeof(properties) = 'object')
);
CREATE INDEX application_resources_type_id
    ON application_resources(application_id, resource_type, resource_id);

ALTER TABLE audit_logs
    ADD COLUMN actor_service_account_id uuid
        REFERENCES service_accounts(id) ON DELETE SET NULL;
ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_one_actor
        CHECK (num_nonnulls(actor_user_id, actor_service_account_id) <= 1);
