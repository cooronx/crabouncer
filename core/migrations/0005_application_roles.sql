ALTER TABLE applications
    ADD CONSTRAINT applications_organization_id_id_unique
        UNIQUE (organization_id, id);

CREATE TABLE application_roles (
    id uuid PRIMARY KEY,
    application_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    key text NOT NULL CHECK (
        key = lower(btrim(key))
        AND (
            key ~ '^[a-z]$'
            OR key ~ '^[a-z][a-z0-9_]{0,62}[a-z0-9]$'
        )
    ),
    display_name text NOT NULL
        CHECK (display_name = btrim(display_name) AND display_name <> ''),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, application_id)
        REFERENCES applications(organization_id, id) ON DELETE RESTRICT,
    UNIQUE (application_id, key),
    UNIQUE (organization_id, id)
);
CREATE INDEX application_roles_application_id
    ON application_roles(application_id);

CREATE TABLE application_role_user_assignments (
    role_id uuid NOT NULL,
    user_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, user_id),
    FOREIGN KEY (organization_id, role_id)
        REFERENCES application_roles(organization_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, user_id)
        REFERENCES users(organization_id, id) ON DELETE RESTRICT
);
CREATE INDEX application_role_user_assignments_user_id
    ON application_role_user_assignments(user_id);

CREATE TABLE application_role_group_assignments (
    role_id uuid NOT NULL,
    group_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, group_id),
    FOREIGN KEY (organization_id, role_id)
        REFERENCES application_roles(organization_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, group_id)
        REFERENCES groups(organization_id, id) ON DELETE RESTRICT
);
CREATE INDEX application_role_group_assignments_group_id
    ON application_role_group_assignments(group_id);
