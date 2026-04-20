package com.loyalty.identity_service.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(
        name = "user_store_scopes",
        indexes = {
                @Index(name = "uq_user_store_scopes",       columnList = "user_id, store_id", unique = true),
                @Index(name = "idx_user_store_scopes_user", columnList = "user_id")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserStoreScope {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "user_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_user_store_scopes_user")
    )
    private AdminUser user;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    /** Brand the store belongs to (owned by a separate brand-service). */
    @Column(name = "brand_id", nullable = false)
    private UUID brandId;

    /** Store that this user is scoped to. */
    @Column(name = "store_id", nullable = false)
    private UUID storeId;

    @Column(name = "assigned_at", nullable = false)
    @Builder.Default
    private OffsetDateTime assignedAt = OffsetDateTime.now();
}
