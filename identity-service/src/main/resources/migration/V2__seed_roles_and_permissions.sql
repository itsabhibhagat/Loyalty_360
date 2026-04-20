-- ============================================================
-- V2__seed_roles_and_permissions.sql
-- Pre-loads the permission catalog and system roles.
-- ============================================================

-- PERMISSIONS
INSERT INTO permissions (id, code, name, category) VALUES
    ('00000000-0000-4000-a000-000000000001', 'customer.read',          'Read customers',              'CUSTOMER'),
    ('00000000-0000-4000-a000-000000000002', 'customer.write',         'Create and update customers',  'CUSTOMER'),
    ('00000000-0000-4000-a000-000000000003', 'customer.adjust_points', 'Adjust points manually',       'CUSTOMER'),
    ('00000000-0000-4000-a000-000000000004', 'customer.delete',        'Delete customers (GDPR)',      'CUSTOMER'),
    ('00000000-0000-4000-a000-000000000005', 'reward.read',            'Read rewards',                 'REWARD'),
    ('00000000-0000-4000-a000-000000000006', 'reward.write',           'Create and update rewards',    'REWARD'),
    ('00000000-0000-4000-a000-000000000007', 'reward.issue',           'Issue reward to customer',     'REWARD'),
    ('00000000-0000-4000-a000-000000000008', 'store.read',             'Read stores',                  'STORE'),
    ('00000000-0000-4000-a000-000000000009', 'store.write',            'Create and update stores',     'STORE'),
    ('00000000-0000-4000-a000-000000000010', 'brand.read',             'Read brand settings',          'BRAND'),
    ('00000000-0000-4000-a000-000000000011', 'brand.write',            'Update brand settings',        'BRAND'),
    ('00000000-0000-4000-a000-000000000012', 'admin_user.manage',      'Manage admin users',           'ADMIN'),
    ('00000000-0000-4000-a000-000000000013', 'role.manage',            'Manage roles and permissions',  'ADMIN'),
    ('00000000-0000-4000-a000-000000000014', 'audit.read',             'View audit log',               'ADMIN'),
    ('00000000-0000-4000-a000-000000000015', 'campaign.read',          'Read campaigns',               'CAMPAIGN'),
    ('00000000-0000-4000-a000-000000000016', 'campaign.write',         'Create and update campaigns',  'CAMPAIGN'),
    ('00000000-0000-4000-a000-000000000017', 'platform.admin',         'Platform operator access',     'PLATFORM');

-- ROLES
INSERT INTO roles (id, tenant_id, code, name, description, is_system) VALUES
    ('10000000-0000-4000-a000-000000000001', NULL,
     'PLATFORM_OPERATOR', 'Platform Operator',
     'Full access to everything including cross-tenant operations', TRUE),
    ('10000000-0000-4000-a000-000000000002', NULL,
     'TENANT_OWNER', 'Tenant Owner',
     'Full access within own tenant. Created during tenant onboarding.', TRUE),
    ('10000000-0000-4000-a000-000000000003', NULL,
     'BRAND_MANAGER', 'Brand Manager',
     'Manages customers, rewards, and campaigns for assigned brands.', TRUE),
    ('10000000-0000-4000-a000-000000000004', NULL,
     'STORE_ADMIN', 'Store Admin',
     'Read-only access limited to assigned stores.', TRUE),
    ('10000000-0000-4000-a000-000000000005', NULL,
     'FINANCE_VIEWER', 'Finance Viewer',
     'Read-only access across the tenant for reporting.', TRUE),
    ('10000000-0000-4000-a000-000000000006', NULL,
     'CUSTOMER_SUPPORT', 'Customer Support',
     'Can manage customer profiles and adjust points.', TRUE);

-- ROLE -> PERMISSION MAPPINGS

-- PLATFORM_OPERATOR gets ALL permissions
INSERT INTO role_permissions (id, role_id, permission_id)
SELECT gen_random_uuid(),
       '10000000-0000-4000-a000-000000000001',
       id
FROM permissions;

-- TENANT_OWNER gets everything EXCEPT platform.admin
INSERT INTO role_permissions (id, role_id, permission_id)
SELECT gen_random_uuid(),
       '10000000-0000-4000-a000-000000000002',
       id
FROM permissions
WHERE code != 'platform.admin';

-- BRAND_MANAGER
INSERT INTO role_permissions (id, role_id, permission_id)
SELECT gen_random_uuid(),
       '10000000-0000-4000-a000-000000000003',
       id
FROM permissions
WHERE code IN (
    'customer.read', 'customer.write', 'customer.adjust_points',
    'reward.read', 'reward.write', 'reward.issue',
    'store.read', 'campaign.read', 'campaign.write', 'audit.read'
);

-- STORE_ADMIN
INSERT INTO role_permissions (id, role_id, permission_id)
SELECT gen_random_uuid(),
       '10000000-0000-4000-a000-000000000004',
       id
FROM permissions
WHERE code IN ('customer.read', 'store.read', 'audit.read');

-- FINANCE_VIEWER (all *.read permissions)
INSERT INTO role_permissions (id, role_id, permission_id)
SELECT gen_random_uuid(),
       '10000000-0000-4000-a000-000000000005',
       id
FROM permissions
WHERE code LIKE '%.read' OR code = 'audit.read';

-- CUSTOMER_SUPPORT
INSERT INTO role_permissions (id, role_id, permission_id)
SELECT gen_random_uuid(),
       '10000000-0000-4000-a000-000000000006',
       id
FROM permissions
WHERE code IN (
    'customer.read', 'customer.write', 'customer.adjust_points',
    'reward.read', 'reward.issue', 'audit.read'
);
