package com.loyalty.identity_service.repository;

import com.loyalty.identity_service.entity.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, UUID> {

    List<UserRole> findByUserId(UUID userId);

    @Modifying
    @Query("DELETE FROM UserRole ur WHERE ur.user.id = :userId")
    void deleteByUserId(@Param("userId") UUID userId);

    @Query("SELECT r.code FROM UserRole ur JOIN ur.role r WHERE ur.user.id = :userId")
    List<String> findRoleCodesByUserId(@Param("userId") UUID userId);

    @Query("SELECT DISTINCT p.code FROM UserRole ur " +
            "JOIN ur.role r " +
            "JOIN r.rolePermissions rp " +
            "JOIN rp.permission p " +
            "WHERE ur.user.id = :userId")
    List<String> findPermissionCodesByUserId(@Param("userId") UUID userId);
}
