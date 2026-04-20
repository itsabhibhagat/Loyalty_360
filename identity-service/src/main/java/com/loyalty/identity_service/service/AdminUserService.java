package com.loyalty.identity_service.service;

import com.loyalty.identity_service.dto.*;
import com.loyalty.identity_service.entity.*;
import com.loyalty.identity_service.exception.ConflictException;
import com.loyalty.identity_service.exception.ForbiddenException;
import com.loyalty.identity_service.exception.ResourceNotFoundException;
import com.loyalty.identity_service.repository.AdminUserRepository;
import com.loyalty.identity_service.repository.RoleRepository;
import com.loyalty.identity_service.repository.UserRoleRepository;
import com.loyalty.identity_service.repository.UserStoreScopeRepository;
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
    private final RoleRepository roleRepository;
    private final AuditService auditService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    private static final String TEMP_PASS_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    private static final SecureRandom RANDOM = new SecureRandom();

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


    /**
     * Creates a new admin user with a temporary password.
     * Steps: validate email uniqueness → generate temp password → hash → insert →
     * assign roles → assign scopes → audit.
     */
    @Transactional
    public CreateAdminUserResponse createUser(UUID tenantId, UUID callerId, CreateAdminUserRequest request) {
        // Check email uniqueness within this tenant
        adminUserRepository.findByTenantIdAndEmailIgnoreCase(tenantId, request.getEmail())
                .ifPresent(u -> {
                    if (u.getStatus() != AdminUserStatus.DELETED) {
                        throw new ConflictException("Email already exists in this tenant");
                    }
                });

        // Generate and hash temp password (BCrypt cost 12)
        String tempPassword = generateTempPassword();
        String hash = passwordEncoder.encode(tempPassword);

        // Insert user
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

        // Assign roles
        if (request.getRoleCodes() != null && !request.getRoleCodes().isEmpty()) {
            List<Role> roles = roleRepository.findByCodeIn(request.getRoleCodes());
            if (roles.size() != request.getRoleCodes().size()) {
                throw new ResourceNotFoundException("One or more roles not found");
            }
            for (Role role : roles) {
                // System roles can be assigned to any tenant; custom roles must belong to same
                // tenant
                if (!role.getIsSystem() && (role.getTenantId() == null || !role.getTenantId().equals(tenantId))) {
                    throw new ForbiddenException("Cannot assign role from another tenant");
                }
                UserRole ur = UserRole.builder()
                        .user(user)
                        .role(role)
                        .tenantId(tenantId)
                        .assignedBy(callerId)
                        .build();
                userRoleRepository.save(ur);
            }
        }

        // Assign store scopes
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

        // Audit log
        auditService.logUserCreated(tenantId, callerId, user.getId());

        // Build response with temp password
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
}
