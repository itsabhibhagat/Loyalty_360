package com.loyalty.identity_service.repository;

import com.loyalty.identity_service.entity.TenantRegistry;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TenantRegistryRepository extends JpaRepository<TenantRegistry, UUID> {
    Optional<TenantRegistry> findBySlug(String slug);
}
