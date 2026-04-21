-- ============================================================
-- V5__update_platform_admin_password.sql
-- Fixes the fabricated password hash from V4 with a valid
-- BCrypt cost-12 hash for 'ChangeMe123!'.
-- ============================================================

UPDATE admin_users
SET password_hash = '$2a$12$AoYNbd97YTLItW5oBV7neeLYwAerO.SAumw1D2qhyjFz8oDRz73iG'
WHERE email = 'mat@loyalty360.io';
