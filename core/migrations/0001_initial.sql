CREATE TYPE organization_status AS ENUM ('active', 'disabled');
CREATE TYPE organization_role AS ENUM ('owner', 'admin', 'member');
CREATE TYPE user_status AS ENUM ('pending', 'active', 'disabled');

CREATE TABLE organizations (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (name = btrim(name) AND name <> ''),
    display_name text NOT NULL CHECK (display_name = btrim(display_name) AND display_name <> ''),
    status organization_status NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    email text NOT NULL UNIQUE CHECK (email = lower(btrim(email)) AND email <> ''),
    display_name text NOT NULL CHECK (display_name = btrim(display_name) AND display_name <> ''),
    role organization_role NOT NULL,
    status user_status NOT NULL DEFAULT 'pending',
    is_system_admin boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX users_organization_id ON users(organization_id);

CREATE TABLE password_credentials (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE activation_tokens (
    token_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    token_hash bytea PRIMARY KEY,
    csrf_hash bytea NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    ip inet,
    user_agent text
);
CREATE INDEX sessions_user_id ON sessions(user_id);
CREATE INDEX sessions_expires_at ON sessions(expires_at);

CREATE TABLE applications (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (name = btrim(name) AND name <> ''),
    client_id text NOT NULL UNIQUE,
    redirect_uris jsonb NOT NULL DEFAULT '[]',
    allowed_scopes jsonb NOT NULL DEFAULT '["openid", "profile"]',
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);
CREATE INDEX applications_organization_id ON applications(organization_id);

CREATE TABLE service_accounts (
    id uuid PRIMARY KEY,
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (name = btrim(name) AND name <> ''),
    client_id text NOT NULL UNIQUE,
    scopes jsonb NOT NULL DEFAULT '["authzen:evaluate"]',
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, name)
);

CREATE TABLE service_account_secrets (
    id uuid PRIMARY KEY,
    service_account_id uuid NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    secret_hash text NOT NULL,
    expires_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE oauth_authorization_codes (
    code_hash bytea PRIMARY KEY,
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    scope text NOT NULL,
    code_challenge text NOT NULL,
    nonce text,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE oauth_refresh_tokens (
    token_hash bytea PRIMARY KEY,
    family_id uuid NOT NULL,
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX oauth_refresh_tokens_family_id ON oauth_refresh_tokens(family_id);

CREATE TABLE policy_workspaces (
    application_id uuid PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
    schema_source text NOT NULL DEFAULT '',
    policies jsonb NOT NULL DEFAULT '[]',
    entities jsonb NOT NULL DEFAULT '[]',
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE policy_releases (
    id uuid PRIMARY KEY,
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    version bigint NOT NULL,
    schema_source text NOT NULL,
    policies jsonb NOT NULL,
    entities jsonb NOT NULL,
    created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, version)
);

CREATE TABLE active_policy_releases (
    application_id uuid PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
    release_id uuid NOT NULL REFERENCES policy_releases(id) ON DELETE RESTRICT,
    activated_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    activated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE decision_logs (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    service_account_id uuid NOT NULL REFERENCES service_accounts(id) ON DELETE RESTRICT,
    request_id text NOT NULL,
    request jsonb NOT NULL,
    decision boolean NOT NULL,
    reason text NOT NULL,
    diagnostics jsonb NOT NULL DEFAULT '{}',
    duration_us bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX decision_logs_tenant_created ON decision_logs(organization_id, created_at DESC);
CREATE INDEX decision_logs_expiry ON decision_logs(created_at);

CREATE TABLE audit_logs (
    id uuid PRIMARY KEY,
    organization_id uuid REFERENCES organizations(id) ON DELETE SET NULL,
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text,
    details jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_tenant_created ON audit_logs(organization_id, created_at DESC);
