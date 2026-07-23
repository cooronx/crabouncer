CREATE TYPE group_kind AS ENUM ('physical', 'virtual');

ALTER TABLE users
    ADD CONSTRAINT users_organization_id_id_unique
        UNIQUE (organization_id, id);

CREATE TABLE groups (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL
        REFERENCES organizations(id) ON DELETE RESTRICT,
    key text NOT NULL CHECK (
        key = lower(btrim(key))
        AND (
            key ~ '^[a-z]$'
            OR key ~ '^[a-z][a-z0-9_]{0,62}[a-z0-9]$'
        )
    ),
    display_name text NOT NULL
        CHECK (display_name = btrim(display_name) AND display_name <> ''),
    kind group_kind NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, key),
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, id, kind)
);
CREATE INDEX groups_organization_id ON groups(organization_id);

CREATE TABLE group_memberships (
    organization_id uuid NOT NULL,
    group_id uuid NOT NULL,
    user_id uuid NOT NULL,
    group_kind group_kind NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id),
    FOREIGN KEY (organization_id, group_id, group_kind)
        REFERENCES groups(organization_id, id, kind) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, user_id)
        REFERENCES users(organization_id, id) ON DELETE RESTRICT
);
CREATE INDEX group_memberships_user_id
    ON group_memberships(user_id);
CREATE UNIQUE INDEX group_memberships_one_physical_per_user
    ON group_memberships(organization_id, user_id)
    WHERE group_kind = 'physical';
