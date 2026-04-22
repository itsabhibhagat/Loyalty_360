package com.loyalty.identity_service.service.impl;

import com.loyalty.identity_service.dto.*;
import com.loyalty.identity_service.entity.*;
import com.loyalty.identity_service.exception.ConflictException;
import com.loyalty.identity_service.exception.ForbiddenException;
import com.loyalty.identity_service.exception.ResourceNotFoundException;
import com.loyalty.identity_service.repository.AdminUserRepository;
import com.loyalty.identity_service.repository.RoleRepository;
import com.loyalty.identity_service.repository.UserRoleRepository;
import com.loyalty.identity_service.repository.UserStoreScopeRepository;
import com.loyalty.identity_service.service.AdminUserService;
import com.loyalty.identity_service.service.AuditService;
import com.loyalty.identity_service.service.RefreshTokenService;
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
public class AdminUserServiceImpl implements AdminUserService {

    private final AdminUserRepository adminUserRepository;
    private final UserRoleRepository userRoleRepository;
    private final UserStoreScopeRepository userStoreScopeRepository;
    private final RoleRepository roleRepository;
    private final AuditService auditService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    private static final String TEMP_PASS_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final List<String> ROLE_HIERARCHY = List.of(
            "PLATFORM_OPERATOR",
            "TENANT_OWNER",
            "BRAND_MANAGER",
            "STORE_ADMIN",
            "CUSTOMER_SUPPORT",
            "FINANCE_VIEWER"
    );

    /**
     * Lists admin users for a tenant, filtered by status, with pagination.
     */
    @Override
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


    /**
     * Creates a new admin user with a temporary password.
     * Steps: validate email uniqueness → generate temp password → hash → insert →
     * assign roles → assign scopes → audit.
     */
    @Override
    @Transactional
    public CreateAdminUserResponse createUser(UUID tenantId, UUID callerId, CreateAdminUserRequest request) {

        // 1. Check email uniqueness
        adminUserRepository.findByTenantIdAndEmailIgnoreCase(tenantId, request.getEmail())
                .ifPresent(u -> {
                    if (u.getStatus() != AdminUserStatus.DELETED) {
                        throw new ConflictException("Email already exists in this tenant");
                    }
                });

        // 2. Fetch roles to assign
        List<Role> roles = List.of();
        if (request.getRoleCodes() != null && !request.getRoleCodes().isEmpty()) {
            roles = roleRepository.findByCodeIn(request.getRoleCodes());

            if (roles.size() != request.getRoleCodes().size()) {
                throw new ResourceNotFoundException("One or more roles not found");
            }
        }

        // 3. Fetch caller roles
        List<String> callerRoles = userRoleRepository.findRoleCodesByUserId(callerId);

        if (callerRoles == null || callerRoles.isEmpty()) {
            throw new ForbiddenException("You have no roles assigned");
        }

        // 4. 🔐 VALIDATE ROLE HIERARCHY (BEFORE creating user)
        for (Role role : roles) {

            if (!canAssignRole(callerRoles, role)) {
                throw new ForbiddenException(
                        "You are not authorized to assign role: " + role.getCode()
                );
            }

            // Tenant validation
            if (!role.getIsSystem() &&
                    (role.getTenantId() == null || !role.getTenantId().equals(tenantId))) {
                throw new ForbiddenException("Cannot assign role from another tenant");
            }
        }

        // 5. Generate temp password
        String tempPassword = generateTempPassword();
        String hash = passwordEncoder.encode(tempPassword);

        // 6. Create user (ONLY AFTER validation)
        AdminUser user = AdminUser.builder()
                .tenantId(tenantId)
                .email(request.getEmail())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .passwordHash(hash)
                .status(AdminUserStatus.ACTIVE)
                .createdBy(callerId)
                .build();

        adminUserRepository.save(user);

        // 7. Assign roles
        for (Role role : roles) {
            UserRole ur = UserRole.builder()
                    .user(user)
                    .role(role)
                    .tenantId(tenantId)
                    .assignedBy(callerId)
                    .build();

            userRoleRepository.save(ur);
        }

        // 8. Assign store scopes
        if (request.getStoreScope() != null && !request.getStoreScope().isEmpty()) {
            UUID defaultBrandId = (request.getBrandScope() != null && !request.getBrandScope().isEmpty())
                    ? request.getBrandScope().get(0)
                    : UUID.fromString("00000000-0000-0000-0000-000000000000");

            for (UUID storeId : request.getStoreScope()) {
                UserStoreScope uss = UserStoreScope.builder()
                        .user(user)
                        .tenantId(tenantId)
                        .brandId(defaultBrandId)
                        .storeId(storeId)
                        .build();

                userStoreScopeRepository.save(uss);
            }
        }

        // 9. Audit log
        auditService.logUserCreated(tenantId, callerId, user.getId());

        // 10. Response
        CreateAdminUserResponse response = new CreateAdminUserResponse();
        response.setUserId(user.getId());
        response.setTenantId(tenantId);
        response.setEmail(user.getEmail());
        response.setFirstName(user.getFirstName());
        response.setLastName(user.getLastName());
        response.setStatus(user.getStatus().name());
        response.setRoles(request.getRoleCodes());
        response.setStoreScope(request.getStoreScope());
        response.setBrandScope(request.getBrandScope());
        response.setTemporaryPassword(tempPassword);
        response.setCreatedAt(user.getCreatedAt() != null ? user.getCreatedAt().toInstant() : null);

        return response;
    }


    /**
     * PATCH update: only non-null fields are applied.
     */
    @Override
    @Transactional
    public UserResponse updateUser(UUID tenantId, UUID id, UpdateAdminUserRequest request) {
        AdminUser user = getTenantUser(tenantId, id);

        if (request.getFirstName() != null)
            user.setFirstName(request.getFirstName());
        if (request.getLastName() != null)
            user.setLastName(request.getLastName());
        if (request.getEmail() != null) {
            if (!user.getEmail().equalsIgnoreCase(request.getEmail())) {
                adminUserRepository.findByTenantIdAndEmailIgnoreCase(tenantId, request.getEmail())
                        .ifPresent(u -> {
                            if (u.getStatus() != AdminUserStatus.DELETED) {
                                throw new ConflictException("Email already exists");
                            }
                        });
                user.setEmail(request.getEmail());
            }
        }

        adminUserRepository.save(user);
        return toUserResponse(user);
    }


    /**
     * Soft-deactivate: sets status to DISABLED and revokes all refresh tokens.
     */
    @Override
    @Transactional
    public void deactivateUser(UUID tenantId, UUID callerId, UUID id) {
        AdminUser user = getTenantUser(tenantId, id);
        user.setStatus(AdminUserStatus.DISABLED);
        adminUserRepository.save(user);

        refreshTokenService.revokeAllUserTokens(id);
        auditService.logUserDeactivated(tenantId, callerId, id);
    }

    /**
     * Full replacement of a user's roles.
     */
    @Override
    @Transactional
    public void assignRoles(UUID tenantId, UUID callerId, UUID id, AssignRolesRequest request) {
        AdminUser user = getTenantUser(tenantId, id);

        userRoleRepository.deleteByUserId(id);

        if (request.getRoleCodes() != null && !request.getRoleCodes().isEmpty()) {
            List<Role> roles = roleRepository.findByCodeIn(request.getRoleCodes());
            for (Role role : roles) {
                UserRole ur = UserRole.builder()
                        .user(user)
                        .role(role)
                        .tenantId(tenantId)
                        .assignedBy(callerId)
                        .build();
                userRoleRepository.save(ur);
            }
        }

        auditService.logRolesAssigned(tenantId, callerId, id);
    }

    /**
     * Full replacement of a user's store scopes.
     */
    @Override
    @Transactional
    public void assignStoreScopes(UUID tenantId, UUID callerId, UUID id, AssignStoreScopesRequest request) {
        AdminUser user = getTenantUser(tenantId, id);

        userStoreScopeRepository.deleteByUserId(id);

        if (request.getScopes() != null) {
            for (var scope : request.getScopes()) {
                UserStoreScope uss = UserStoreScope.builder()
                        .user(user)
                        .tenantId(tenantId)
                        .brandId(scope.getBrandId())
                        .storeId(scope.getStoreId())
                        .build();
                userStoreScopeRepository.save(uss);
            }
        }

        auditService.logStoreScopesAssigned(tenantId, callerId, id);
    }

    // ── Private helpers ──────────────────────────────────────────────

    private AdminUser getTenantUser(UUID tenantId, UUID userId) {
        AdminUser user = adminUserRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        if (!user.getTenantId().equals(tenantId)) {
            throw new ResourceNotFoundException("User not found in tenant");
        }
        return user;
    }


    private String generateTempPassword() {
        StringBuilder sb = new StringBuilder(16);
        // Ensure at least one uppercase, one lowercase, one digit, one special
        sb.append(TEMP_PASS_CHARS.charAt(RANDOM.nextInt(26))); // uppercase A-Z
        sb.append(TEMP_PASS_CHARS.charAt(26 + RANDOM.nextInt(26))); // lowercase a-z
        sb.append(TEMP_PASS_CHARS.charAt(52 + RANDOM.nextInt(10))); // digit 0-9
        sb.append(TEMP_PASS_CHARS.charAt(62 + RANDOM.nextInt(8))); // special char
        for (int i = 4; i < 16; i++) {
            sb.append(TEMP_PASS_CHARS.charAt(RANDOM.nextInt(TEMP_PASS_CHARS.length())));
        }
        // Shuffle to avoid predictable positions
        char[] chars = sb.toString().toCharArray();
        for (int i = chars.length - 1; i > 0; i--) {
            int j = RANDOM.nextInt(i + 1);
            char temp = chars[i];
            chars[i] = chars[j];
            chars[j] = temp;
        }
        return new String(chars);
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

    private boolean canAssignRole(List<String> callerRoles, Role targetRole) {

        String targetCode = targetRole.getCode().toUpperCase();
        int targetLevel = ROLE_HIERARCHY.indexOf(targetCode);

        if (targetLevel == -1) {
            throw new ForbiddenException("Invalid or unauthorized role: " + targetRole.getCode());
        }

        int callerBestLevel = callerRoles.stream()
                .map(role -> ROLE_HIERARCHY.indexOf(role))
                .filter(i -> i != -1)
                .min(Integer::compareTo)
                .orElseThrow(() -> new ForbiddenException("Caller has no valid roles"));

        return callerBestLevel < targetLevel;
    }
}
