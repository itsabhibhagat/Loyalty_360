package com.loyalty.identity_service.repository;

import com.loyalty.identity_service.entity.UserStoreScope;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface UserStoreScopeRepository extends JpaRepository<UserStoreScope, UUID> {

    List<UserStoreScope> findByUserId(UUID userId);

    @Modifying
    @Query("DELETE FROM UserStoreScope uss WHERE uss.user.id = :userId")
    void deleteByUserId(@Param("userId") UUID userId);
}
