-- ============================================================
-- V3__add_tenant_registry.sql
-- Minimal mirror of tenants from admin-core.
-- ============================================================

CREATE TABLE tenant_registry (
    id              UUID            PRIMARY KEY,
    slug            VARCHAR(50)     NOT NULL UNIQUE,
    status          VARCHAR(20)     NOT NULL DEFAULT 'ACTIVE',
    synced_at       TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);
