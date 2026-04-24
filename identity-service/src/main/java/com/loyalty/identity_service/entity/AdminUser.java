package com.loyalty.identity_service.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity

@Table(

        name = "admin_users",

        indexes = {

                @Index(name = "idx_admin_users_tenant", columnList = "tenant_id")

        }

)

@Getter

@Setter

@NoArgsConstructor

@AllArgsConstructor

@Builder

public class AdminUser {

    @Id

    @GeneratedValue(strategy = GenerationType.UUID)

    @Column(name = "id", updatable = false, nullable = false)

    private UUID id;

    @Column(name = "tenant_id", nullable = false)

    private UUID tenantId;

    @Column(name = "email", nullable = false, length = 255)

    private String email;

    @Column(name = "password_hash", nullable = false, length = 72)

    private String passwordHash;

    @Column(name = "first_name", nullable = false, length = 100)

    private String firstName;

    @Column(name = "last_name", nullable = false, length = 100)

    private String lastName;

    /**

     * Stored as VARCHAR(20) in the DB — matches the Flyway DDL.

     * EnumType.STRING persists the enum name (e.g. "ACTIVE"), never

     * the ordinal, so re-ordering enum constants is always safe.

     */

    @Enumerated(EnumType.STRING)

    @Column(name = "status", nullable = false, length = 20)

    @Builder.Default

    private AdminUserStatus status = AdminUserStatus.ACTIVE;

    @Column(name = "email_verified", nullable = false)

    @Builder.Default

    private Boolean emailVerified = false;

    @Column(name = "mfa_enabled", nullable = false)

    @Builder.Default

    private Boolean mfaEnabled = false;

    @Column(name = "mfa_secret", length = 255)

    private String mfaSecret;

    @Column(name = "last_login_at")

    private OffsetDateTime lastLoginAt;

    @Column(name = "failed_login_count", nullable = false)

    @Builder.Default

    private Integer failedLoginCount = 0;

    @Column(name = "locked_until")

    private OffsetDateTime lockedUntil;

    @CreationTimestamp

    @Column(name = "created_at", nullable = false, updatable = false)

    private OffsetDateTime createdAt;

    @Column(name = "created_by")

    private UUID createdBy;

    @UpdateTimestamp

    @Column(name = "updated_at", nullable = false)

    private OffsetDateTime updatedAt;

    @Version

    @Column(name = "version", nullable = false)

    private Long version;

    // ── Relationships ────────────────────────────────────────────────────────

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)

    @Builder.Default

    private List<UserRole> userRoles = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)

    @Builder.Default

    private List<UserStoreScope> userStoreScopes = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)

    @Builder.Default

    private List<RefreshToken> refreshTokens = new ArrayList<>();

    // ── Convenience helpers ──────────────────────────────────────────────────

    public boolean isActive() {

        return AdminUserStatus.ACTIVE == this.status;

    }

    public boolean isDeleted() {

        return AdminUserStatus.DELETED == this.status;

    }

    /**

     * Considers both the enum status AND a time-bounded lock from

     * failed login attempts.

     */

    public boolean isLocked() {
        return AdminUserStatus.LOCKED == this.status
                && lockedUntil != null
                && OffsetDateTime.now().isBefore(lockedUntil); // AND, not OR
    }

}
