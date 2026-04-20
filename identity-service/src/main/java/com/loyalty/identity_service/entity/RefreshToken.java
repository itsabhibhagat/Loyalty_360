package com.loyalty.identity_service.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(
        name = "refresh_tokens",
        indexes = {
                @Index(name = "idx_refresh_tokens_user",   columnList = "user_id"),
                @Index(name = "idx_refresh_tokens_family", columnList = "token_family"),
                // Partial index (WHERE revoked_at IS NULL) is defined in the Flyway migration.
                // JPA cannot express partial indexes via @Index, so it is managed in SQL only.
                @Index(name = "idx_refresh_tokens_hash",   columnList = "token_hash")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "user_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_refresh_tokens_user")
    )
    private AdminUser user;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    /** SHA-256 (or similar) hash of the raw token — never store the raw value. */
    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    /**
     * All tokens in the same rotation chain share a family UUID.
     * Detecting a reuse of any revoked token in the family triggers
     * invalidation of the entire family (theft detection).
     */
    @Column(name = "token_family", nullable = false)
    private UUID tokenFamily;

    @CreationTimestamp
    @Column(name = "issued_at", nullable = false, updatable = false)
    private OffsetDateTime issuedAt;

    @Column(name = "expires_at", nullable = false)
    private OffsetDateTime expiresAt;

    @Column(name = "revoked_at")
    private OffsetDateTime revokedAt;

    @Column(name = "revoke_reason", length = 30)
    private String revokeReason;

    /** Points to the token that superseded this one during rotation. */
    @Column(name = "replaced_by_token_id")
    private UUID replacedByTokenId;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    // ── Convenience helpers ──────────────────────────────────────────────────

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired() {
        return OffsetDateTime.now().isAfter(expiresAt);
    }

    public boolean isActive() {
        return !isRevoked() && !isExpired();
    }
}