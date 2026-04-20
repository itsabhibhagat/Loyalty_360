package com.loyalty.identity_service.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Append-only audit log for every authentication-related event.
 *
 * Intentionally has NO foreign keys — actor_id is a loose UUID reference
 * so that log rows are preserved even when the actor's account is deleted.
 * Never update or delete rows from this table.
 */
@Entity
@Table(
        name = "auth_audit_logs",
        indexes = {
                @Index(name = "idx_auth_audit_tenant_time", columnList = "tenant_id, occurred_at"),
                @Index(name = "idx_auth_audit_actor",       columnList = "actor_type, actor_id"),
                @Index(name = "idx_auth_audit_event",       columnList = "event_type, occurred_at")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthAuditLog {

    /** BIGSERIAL in Postgres — auto-incremented by the DB sequence. */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", updatable = false, nullable = false)
    private Long id;

    /** May be null for events where the tenant cannot be determined (e.g. unknown subdomain). */
    @Column(name = "tenant_id")
    private UUID tenantId;

    /** Discriminator for the actor, e.g. "ADMIN_USER", "SYSTEM", "API_KEY". */
    @Column(name = "actor_type", nullable = false, length = 20)
    private String actorType;

    /**
     * Loose UUID reference to the actor — no FK by design.
     * Use in combination with actor_type to resolve the originating entity.
     */
    @Column(name = "actor_id")
    private UUID actorId;

    @Column(name = "actor_email", length = 255)
    private String actorEmail;

    /** e.g. "LOGIN_SUCCESS", "LOGIN_FAILURE", "PASSWORD_RESET", "MFA_CHALLENGE". */
    @Column(name = "event_type", nullable = false, length = 50)
    private String eventType;

    @Column(name = "success", nullable = false)
    private Boolean success;

    @Column(name = "failure_reason", columnDefinition = "TEXT")
    private String failureReason;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    /** Links related events in a single request/flow (e.g. tracing correlation). */
    @Column(name = "correlation_id")
    private UUID correlationId;

    @Column(name = "occurred_at", nullable = false)
    @Builder.Default
    private OffsetDateTime occurredAt = OffsetDateTime.now();
}