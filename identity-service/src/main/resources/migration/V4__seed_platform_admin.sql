-- ============================================================
-- V4__seed_platform_admin.sql
-- Creates the platform tenant and first admin user.
-- WARNING: Change the password hash before deploying to production.
-- The password below is 'ChangeMe123!' hashed with BCrypt cost 12.
-- ============================================================

INSERT INTO tenant_registry (id, slug, status) VALUES
    ('00000000-0000-4000-b000-000000000001', 'platform', 'ACTIVE');

INSERT INTO admin_users (id, tenant_id, email, password_hash, first_name, last_name, status)
VALUES (
    '00000000-0000-4000-b000-000000000002',
    '00000000-0000-4000-b000-000000000001',
    'mat@loyalty360.io',
    '$2a$12$LJ3m4ys3Rz0G5kFn8V7Y2eHm3Fy1Kv1Xl8dP7Yb6Z5nQ9wR1sT3u',
    'Mat', 'Admin', 'ACTIVE'
);

INSERT INTO user_roles (id, user_id, role_id, tenant_id) VALUES (
    gen_random_uuid(),
    '00000000-0000-4000-b000-000000000002',
    '10000000-0000-4000-a000-000000000001',
    '00000000-0000-4000-b000-000000000001'
);
