package com.loyalty.identity_service.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Local read-only mirror of tenant data synced from admin-core.
 * Matches Flyway V3 schema: id, slug, status, synced_at only.
 */
@Entity
@Table(name = "tenant_registry")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantRegistry {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "slug", nullable = false, unique = true, length = 50)
    private String slug;

    @Column(name = "status", nullable = false, length = 20)
    @Builder.Default
    private String status = "ACTIVE";

    @Column(name = "synced_at", nullable = false)
    @Builder.Default
    private OffsetDateTime syncedAt = OffsetDateTime.now();
}