package com.loyalty.identity_service.service.impl;

import com.loyalty.identity_service.config.JwtService;
import com.loyalty.identity_service.dto.*;
import com.loyalty.identity_service.entity.AdminUser;
import com.loyalty.identity_service.entity.AdminUserStatus;
import com.loyalty.identity_service.entity.RefreshToken;
import com.loyalty.identity_service.entity.TenantRegistry;
import com.loyalty.identity_service.exception.UnauthorizedException;
import com.loyalty.identity_service.repository.AdminUserRepository;
import com.loyalty.identity_service.repository.TenantRegistryRepository;
import com.loyalty.identity_service.repository.UserRoleRepository;
import com.loyalty.identity_service.repository.UserStoreScopeRepository;
import com.loyalty.identity_service.service.AuditService;
import com.loyalty.identity_service.service.AuthService;
import com.loyalty.identity_service.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final AdminUserRepository adminUserRepository;
    private final TenantRegistryRepository tenantRegistryRepository;
    private final UserRoleRepository userRoleRepository;
    private final UserStoreScopeRepository userStoreScopeRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuditService auditService;

    @Value("${app.security.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${app.security.lock-duration-minutes:30}")
    private int lockDurationMinutes;

    @Override
    @Transactional(noRollbackFor = {
            UnauthorizedException.class
    })
    public AuthResponse login(LoginRequest request, String ipAddress, String userAgent)  {
        // Step 1-3: Lookup tenant
        TenantRegistry tenant = tenantRegistryRepository.findBySlug(request.getTenantSlug())
                .filter(t -> "ACTIVE".equals(t.getStatus()))
                .orElse(null);

        if (tenant == null) {
            auditService.logLoginFailed(null, request.getEmail(), "Tenant not found or inactive", ipAddress, userAgent);
            throw new UnauthorizedException("Invalid credentials");
        }

        // Step 4-5: Lookup user
        AdminUser user = adminUserRepository.findByTenantIdAndEmailIgnoreCase(tenant.getId(), request.getEmail())
                .orElse(null);

        if (user == null) {
            auditService.logLoginFailed(tenant.getId(), request.getEmail(), "User not found", ipAddress, userAgent);
            throw new UnauthorizedException("Invalid credentials");
        }

        // Step 6: Check status and lockout
        if (user.getStatus() == AdminUserStatus.DISABLED || user.getStatus() == AdminUserStatus.DELETED) {
            auditService.logLoginFailedWithUser(user, "Account disabled", ipAddress, userAgent);
            throw new UnauthorizedException("Invalid credentials");
        }

        // Block if actively locked
        if (user.isLocked()) {
            auditService.logLoginFailedWithUser(user, "Account locked", ipAddress, userAgent);
            throw new UnauthorizedException("Account temporarily locked. Try again later.");
        }

// Unlock if lock window has expired
        if (user.getStatus() == AdminUserStatus.LOCKED) {
            user.setStatus(AdminUserStatus.ACTIVE);
            user.setFailedLoginCount(0);
            // don't save here — it'll be saved after password check below
        }

        // Step 7: Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            int failures = user.getFailedLoginCount() + 1;
            user.setFailedLoginCount(failures);
            if (failures >= maxFailedAttempts) {
                user.setStatus(AdminUserStatus.LOCKED);
                user.setLockedUntil(OffsetDateTime.now().plusMinutes(lockDurationMinutes));
            }
            adminUserRepository.save(user);
            auditService.logLoginFailedWithUser(user, "Invalid password", ipAddress, userAgent);
            throw new UnauthorizedException("Invalid credentials");
        }

        // Step 8: Success
        user.setFailedLoginCount(0);
        user.setLockedUntil(null);
        user.setLastLoginAt(OffsetDateTime.now());
        adminUserRepository.save(user);

        // Build response (steps 9-17)
        return buildAuthResponse(user, tenant, UUID.randomUUID(), ipAddress, userAgent, false);
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getCurrentUser(String token) {
        // Step 1-3
        UUID userId = jwtService.extractUserId(token);

        // Step 4: Load from DB to get fresh permissions
        AdminUser user = adminUserRepository.findById(userId)
                .orElseThrow(() -> new UnauthorizedException("User not found"));

        if (!user.isActive()) {
            throw new UnauthorizedException("User account is not active");
        }

        TenantRegistry tenant = tenantRegistryRepository.findById(user.getTenantId())
                .orElseThrow(
                        () -> new UnauthorizedException("Tenant not found"));

        return buildUserResponse(user, tenant);
    }

    @Override
    @Transactional
    public AuthResponse refresh(RefreshRequest request, String ipAddress, String userAgent) {
        RefreshToken token = refreshTokenService.validateAndGetToken(request.getRefreshToken());

        if (token == null) {
            throw new UnauthorizedException("Invalid or expired refresh token");
        }

        AdminUser user = token.getUser();
        if (!user.isActive()) {
            throw new UnauthorizedException("User account is not active");
        }

        TenantRegistry tenant = tenantRegistryRepository.findById(user.getTenantId())
                .orElseThrow(
                        () -> new UnauthorizedException("Tenant not found"));

        String newRefreshToken = refreshTokenService.rotateToken(token, user, tenant, ipAddress, userAgent);

        AuthResponse res = buildAuthResponse(user, tenant, token.getTokenFamily(), ipAddress, userAgent, true);
        // Override the token with the rotated one
        res.setRefreshToken(newRefreshToken);

        auditService.logTokenRefreshed(user, ipAddress, userAgent);

        return res;
    }

    @Override
    @Transactional
    public void logout(LogoutRequest request) {
        refreshTokenService.revokeToken(request.getRefreshToken());
        // For audit parsing, we lookup the token to get the user
        String hash = RefreshTokenServiceImpl.sha256Hex(request.getRefreshToken());
        refreshTokenService.validateAndGetToken(hash); // won't return anything if just revoked, but let's lookup
        // manually
    }

    private AuthResponse buildAuthResponse(AdminUser user, TenantRegistry tenant, UUID tokenFamily,
                                           String ipAddress, String userAgent, boolean isRefresh) {
        List<String> roles = userRoleRepository.findRoleCodesByUserId(user.getId());
        List<String> permissions = userRoleRepository.findPermissionCodesByUserId(user.getId());

        var scopes = userStoreScopeRepository.findByUserId(user.getId());
        List<UUID> brandScope = scopes.stream().map(s -> s.getBrandId()).distinct().collect(Collectors.toList());
        List<UUID> storeScope = scopes.stream().map(s -> s.getStoreId()).distinct().collect(Collectors.toList());

        String accessToken = jwtService.generateAccessToken(user, tenant, roles, permissions, brandScope, storeScope);

        String refreshToken = null;
        if (!isRefresh) {
            refreshToken = refreshTokenService.issueRefreshToken(user, tenant, tokenFamily, ipAddress, userAgent);
            auditService.logLoginSuccess(user, ipAddress, userAgent);
        }

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTokenExpirySeconds())
                .user(buildUserResponse(user, tenant, roles, permissions, brandScope, storeScope))
                .build();
    }

    private UserResponse buildUserResponse(AdminUser user, TenantRegistry tenant) {
        List<String> roles = userRoleRepository.findRoleCodesByUserId(user.getId());
        List<String> permissions = userRoleRepository.findPermissionCodesByUserId(user.getId());

        var scopes = userStoreScopeRepository.findByUserId(user.getId());
        List<UUID> brandScope = scopes.stream().map(s -> s.getBrandId()).distinct().collect(Collectors.toList());
        List<UUID> storeScope = scopes.stream().map(s -> s.getStoreId()).distinct().collect(Collectors.toList());

        return buildUserResponse(user, tenant, roles, permissions, brandScope, storeScope);
    }

    private UserResponse buildUserResponse(AdminUser user, TenantRegistry tenant,
                                           List<String> roles, List<String> permissions,
                                           List<UUID> brandScope, List<UUID> storeScope) {
        return UserResponse.builder()
                .userId(user.getId())
                .tenantId(tenant.getId())
                .tenantSlug(tenant.getSlug())
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
    }}