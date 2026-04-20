-- ============================================================
-- V1__init_identity.sql
-- identity-service schema for auth_db
-- ============================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. admin_users
CREATE TABLE admin_users (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID            NOT NULL,
    email               VARCHAR(255)    NOT NULL,
    password_hash       VARCHAR(72)     NOT NULL,
    first_name          VARCHAR(100)    NOT NULL,
    last_name           VARCHAR(100)    NOT NULL,
    status              VARCHAR(20)     NOT NULL DEFAULT 'ACTIVE',
    email_verified      BOOLEAN         NOT NULL DEFAULT FALSE,
    mfa_enabled         BOOLEAN         NOT NULL DEFAULT FALSE,
    mfa_secret          VARCHAR(255),
    last_login_at       TIMESTAMPTZ,
    failed_login_count  INT             NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    created_by          UUID,
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    version             BIGINT          NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX uq_admin_users_tenant_email
    ON admin_users(tenant_id, LOWER(email))
    WHERE status != 'DELETED';

CREATE INDEX idx_admin_users_tenant
    ON admin_users(tenant_id);

-- 2. roles
CREATE TABLE roles (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID,
    code                VARCHAR(50)     NOT NULL,
    name                VARCHAR(150)    NOT NULL,
    description         TEXT,
    is_system           BOOLEAN         NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    version             BIGINT          NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX uq_roles_code
    ON roles(COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'), code);

-- 3. permissions
CREATE TABLE permissions (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    code                VARCHAR(100)    NOT NULL UNIQUE,
    name                VARCHAR(150)    NOT NULL,
    description         TEXT,
    category            VARCHAR(50)     NOT NULL,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- 4. user_roles
CREATE TABLE user_roles (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID            NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    role_id             UUID            NOT NULL REFERENCES roles(id),
    tenant_id           UUID            NOT NULL,
    assigned_by         UUID,
    assigned_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX uq_user_roles
    ON user_roles(user_id, role_id);
CREATE INDEX idx_user_roles_user
    ON user_roles(user_id);

-- 5. role_permissions
CREATE TABLE role_permissions (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id             UUID            NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id       UUID            NOT NULL REFERENCES permissions(id),
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX uq_role_permissions
    ON role_permissions(role_id, permission_id);

-- 6. user_store_scopes
CREATE TABLE user_store_scopes (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID            NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    tenant_id           UUID            NOT NULL,
    brand_id            UUID            NOT NULL,
    store_id            UUID            NOT NULL,
    assigned_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX uq_user_store_scopes
    ON user_store_scopes(user_id, store_id);
CREATE INDEX idx_user_store_scopes_user
    ON user_store_scopes(user_id);

-- 7. refresh_tokens
CREATE TABLE refresh_tokens (
    id                      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID            NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    tenant_id               UUID            NOT NULL,
    token_hash              VARCHAR(64)     NOT NULL UNIQUE,
    token_family            UUID            NOT NULL,
    issued_at               TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at              TIMESTAMPTZ     NOT NULL,
    revoked_at              TIMESTAMPTZ,
    revoke_reason           VARCHAR(30),
    replaced_by_token_id    UUID,
    ip_address              VARCHAR(45),
    user_agent              VARCHAR(500)
);

CREATE INDEX idx_refresh_tokens_user
    ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_family
    ON refresh_tokens(token_family);
CREATE INDEX idx_refresh_tokens_hash
    ON refresh_tokens(token_hash)
    WHERE revoked_at IS NULL;

-- 8. auth_audit_logs
CREATE TABLE auth_audit_logs (
    id                  BIGSERIAL       PRIMARY KEY,
    tenant_id           UUID,
    actor_type          VARCHAR(20)     NOT NULL,
    actor_id            UUID,
    actor_email         VARCHAR(255),
    event_type          VARCHAR(50)     NOT NULL,
    success             BOOLEAN         NOT NULL,
    failure_reason      TEXT,
    ip_address          VARCHAR(45),
    user_agent          VARCHAR(500),
    correlation_id      UUID,
    occurred_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_audit_tenant_time
    ON auth_audit_logs(tenant_id, occurred_at DESC);
CREATE INDEX idx_auth_audit_actor
    ON auth_audit_logs(actor_type, actor_id);
CREATE INDEX idx_auth_audit_event
    ON auth_audit_logs(event_type, occurred_at DESC);
