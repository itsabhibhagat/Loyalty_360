package com.loyalty.identity_service.repository;

import com.loyalty.identity_service.entity.AdminUser;
import com.loyalty.identity_service.entity.AdminUserStatus;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AdminUserRepository extends JpaRepository<AdminUser, UUID> {

    Optional<AdminUser> findByTenantIdAndEmailIgnoreCase(UUID tenantId, String email);

    Page<AdminUser> findByTenantIdAndStatus(UUID tenantId, AdminUserStatus status, Pageable pageable);

    Page<AdminUser> findByTenantId(UUID tenantId, Pageable pageable);
}
