package com.loyalty.identity_service.service;

import com.loyalty.identity_service.dto.*;
import com.loyalty.identity_service.entity.*;
import com.loyalty.identity_service.exception.ConflictException;
import com.loyalty.identity_service.exception.ForbiddenException;
import com.loyalty.identity_service.exception.ResourceNotFoundException;
import com.loyalty.identity_service.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminUserService {

    private final AdminUserRepository adminUserRepository;
    private final UserRoleRepository userRoleRepository;
    private final UserStoreScopeRepository userStoreScopeRepository;

    /**
     * Lists admin users for a tenant, filtered by status, with pagination.
     */
    @Transactional(readOnly = true)
    public Page<UserResponse> listUsers(UUID tenantId, String status, Pageable pageable) {
        Page<AdminUser> usersPage;

        if (status != null && !status.isBlank()) {
            try {
                AdminUserStatus statusEnum = AdminUserStatus.valueOf(status.toUpperCase());
                usersPage = adminUserRepository.findByTenantIdAndStatus(tenantId, statusEnum, pageable);
            } catch (IllegalArgumentException e) {
                usersPage = adminUserRepository.findByTenantId(tenantId, pageable);
            }
        } else {
            usersPage = adminUserRepository.findByTenantId(tenantId, pageable);
        }

        return usersPage.map(this::toUserResponse);
    }


    private UserResponse toUserResponse(AdminUser user) {
        List<String> roles = userRoleRepository.findRoleCodesByUserId(user.getId());
        List<String> permissions = userRoleRepository.findPermissionCodesByUserId(user.getId());
        var scopes = userStoreScopeRepository.findByUserId(user.getId());
        List<UUID> brandScope = scopes.stream().map(UserStoreScope::getBrandId).distinct().collect(Collectors.toList());
        List<UUID> storeScope = scopes.stream().map(UserStoreScope::getStoreId).distinct().collect(Collectors.toList());

        return UserResponse.builder()
                .userId(user.getId())
                .tenantId(user.getTenantId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .status(user.getStatus().name())
                .roles(roles)
                .permissions(permissions)
                .brandScope(brandScope)
                .storeScope(storeScope)
                .createdAt(user.getCreatedAt() != null ? user.getCreatedAt().toInstant() : null)
                .build();
    }




}
