package com.loyalty.identity_service.entity;

/**
 * Lifecycle states for an admin user account.
 * Stored as VARCHAR(20) in the database via @Enumerated(EnumType.STRING).
 */
public enum AdminUserStatus {
    ACTIVE,
    DISABLED,
    LOCKED,
    DELETED
}