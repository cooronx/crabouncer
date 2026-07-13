CREATE TABLE users (
    id uuid PRIMARY KEY,
    username text NOT NULL UNIQUE CHECK (username = btrim(username) AND username <> ''),
    email text,
    display_name text NOT NULL CHECK (display_name = btrim(display_name) AND display_name <> ''),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    is_system_admin boolean NOT NULL DEFAULT false,
    must_change_password boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX one_system_admin ON users (is_system_admin) WHERE is_system_admin;

CREATE TABLE password_credentials (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE organizations (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (name = btrim(name) AND name <> ''),
    display_name text NOT NULL CHECK (display_name = btrim(display_name) AND display_name <> ''),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'deleted')),
    is_system boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX one_system_organization ON organizations (is_system) WHERE is_system;

CREATE TABLE organization_memberships (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id)
);

CREATE UNIQUE INDEX one_owner_per_organization
    ON organization_memberships (organization_id) WHERE role = 'owner';

CREATE TABLE sessions (
    id_hash bytea PRIMARY KEY,
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
    client_secret_hash bytea NOT NULL,
    redirect_uris jsonb NOT NULL DEFAULT '[]',
    allowed_scopes jsonb NOT NULL DEFAULT '[]',
    access_token_ttl integer NOT NULL DEFAULT 900 CHECK (access_token_ttl BETWEEN 60 AND 86400),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name),
    UNIQUE (id, organization_id)
);

CREATE TABLE roles (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    application_id uuid NOT NULL,
    name text NOT NULL CHECK (name = btrim(name) AND name <> ''),
    display_name text NOT NULL CHECK (display_name = btrim(display_name) AND display_name <> ''),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, name),
    FOREIGN KEY (application_id, organization_id)
        REFERENCES applications(id, organization_id) ON DELETE CASCADE
);

CREATE TABLE user_roles (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE cedar_schemas (
    application_id uuid PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
    source text NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE cedar_policies (
    id uuid PRIMARY KEY,
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (name = btrim(name) AND name <> ''),
    draft_source text NOT NULL,
    published_source text,
    enabled boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, name),
    CHECK (NOT enabled OR published_source IS NOT NULL)
);
