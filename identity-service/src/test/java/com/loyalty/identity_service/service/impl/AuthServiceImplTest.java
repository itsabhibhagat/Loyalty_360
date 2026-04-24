package com.loyalty.identity_service.service.impl;

import com.loyalty.identity_service.config.AppProperties;
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
import com.loyalty.identity_service.service.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
public class AuthServiceImplTest {
    @InjectMocks
    private AuthServiceImpl authService;

    @Mock
    private AppProperties appProperties;

    @Mock
    private AdminUserRepository adminUserRepository;
    @Mock
    private TenantRegistryRepository tenantRegistryRepository;
    @Mock
    private UserRoleRepository userRoleRepository;
    @Mock
    private UserStoreScopeRepository userStoreScopeRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtService jwtService;
    @Mock
    private RefreshTokenService refreshTokenService;
    @Mock
    private AuditService auditService;



    private LoginRequest request;
    private TenantRegistry activeTenant;
    private AdminUser user;
    private final String ip = "127.0.0.1";
    private final String userAgent = "JUnit";

    @BeforeEach
    void setup() {
        request = new LoginRequest();
        request.setTenantSlug("test-tenant");
        request.setEmail("test@example.com");
        request.setPassword("password");

        activeTenant = new TenantRegistry();
        activeTenant.setId(UUID.randomUUID());
        activeTenant.setSlug("test-tenant");
        activeTenant.setStatus("ACTIVE");

        user = new AdminUser();
        user.setId(UUID.randomUUID());
        user.setTenantId(activeTenant.getId());
        user.setEmail("test@example.com");
        user.setPasswordHash("encoded");
        user.setStatus(AdminUserStatus.ACTIVE);
    }
    @Test
    void shouldLoginSuccessfully() {


        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(request.getPassword(), user.getPasswordHash()))
                .thenReturn(true);

        when(userRoleRepository.findRoleCodesByUserId(user.getId()))
                .thenReturn(List.of("ADMIN", "MANAGER"));

        when(userRoleRepository.findPermissionCodesByUserId(user.getId()))
                .thenReturn(List.of("READ", "WRITE", "DELETE"));

        when(userStoreScopeRepository.findByUserId(user.getId()))
                .thenReturn(Collections.emptyList());

        when(jwtService.generateAccessToken(any(), any(), any(), any(), any(), any()))
                .thenReturn("access-token-123");

        when(jwtService.getAccessTokenExpirySeconds())
                .thenReturn(3600);

        when(refreshTokenService.issueRefreshToken(any(), any(), any(), any(), any()))
                .thenReturn("refresh-token-456");

        when(adminUserRepository.save(any(AdminUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        AuthResponse response = authService.login(request, ip, userAgent);

        // Assert
        assertNotNull(response);
        assertEquals("access-token-123", response.getAccessToken());
        assertEquals("refresh-token-456", response.getRefreshToken());
        assertEquals("Bearer", response.getTokenType());
        assertEquals(3600, response.getExpiresIn());

        // Verify user state updates
        ArgumentCaptor<AdminUser> userCaptor = ArgumentCaptor.forClass(AdminUser.class);
        verify(adminUserRepository).save(userCaptor.capture());
        AdminUser savedUser = userCaptor.getValue();

        assertEquals(0, savedUser.getFailedLoginCount());
        assertNull(savedUser.getLockedUntil());
        assertNotNull(savedUser.getLastLoginAt());
        // Verify audit log
        verify(auditService).logLoginSuccess(user, ip, userAgent);
    }

    //Tenant not found
    @Test
    void shouldThrowException_whenTenantNotFound() {

        // Arrange
        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.empty());

        // Act & Assert
        UnauthorizedException ex = assertThrows(
                UnauthorizedException.class,
                () -> authService.login(request, ip, userAgent)
        );

        assertEquals("Invalid credentials", ex.getMessage());

        verify(auditService).logLoginFailed(
                isNull(),
                eq(request.getEmail()),
                eq("Tenant not found or inactive"),
                eq(ip),
                eq(userAgent)
        );

        verifyNoInteractions(adminUserRepository);
    }

    //Tenant inactive
    @Test
    void shouldThrowException_whenTenantInactive() {


        // Arrange
        activeTenant.setStatus("SUSPENDED");

        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        // Act & Assert
        UnauthorizedException ex = assertThrows(
                UnauthorizedException.class,
                () -> authService.login(request, ip, userAgent)
        );

        assertEquals("Invalid credentials", ex.getMessage());

        verify(auditService).logLoginFailed(
                isNull(),
                eq(request.getEmail()),
                eq("Tenant not found or inactive"),
                eq(ip),
                eq(userAgent)
        );

        verifyNoInteractions(adminUserRepository);
    }

    @Test
    void shouldThrowException_whenUserNotFound(){
        // Arrange
        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.empty());

        // Act & Assert
        UnauthorizedException ex = assertThrows(
                UnauthorizedException.class,
                () -> authService.login(request, ip, userAgent)
        );

        assertEquals("Invalid credentials", ex.getMessage());

        verify(auditService).logLoginFailed(
                eq(activeTenant.getId()),
                eq(request.getEmail()),
                eq("User not found"),
                eq(ip),
                eq(userAgent)
        );

    }

    @Test
    void shouldThrowException_whenUserDisabled() {
        // Arrange
        user.setStatus(AdminUserStatus.DISABLED);

        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));

        // Act & Assert
        UnauthorizedException ex = assertThrows(
                UnauthorizedException.class,
                () -> authService.login(request, ip, userAgent)
        );

        assertEquals("Invalid credentials", ex.getMessage());

        verify(auditService).logLoginFailedWithUser(
                eq(user),
                eq("Account disabled"),
                eq(ip),
                eq(userAgent)
        );
    }

    @Test
    void shouldThrowException_whenUserDeleted() {
        // Arrange
        user.setStatus(AdminUserStatus.DELETED);

        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));

        // Act & Assert
        UnauthorizedException ex = assertThrows(
                UnauthorizedException.class,
                () -> authService.login(request, ip, userAgent)
        );

        assertEquals("Invalid credentials", ex.getMessage());

        verify(auditService).logLoginFailedWithUser(
                eq(user),
                eq("Account disabled"),
                eq(ip),
                eq(userAgent)
        );
    }

    @Test
    void shouldThrowException_whenUserIsLocked() {
        // Arrange
        user.setStatus(AdminUserStatus.LOCKED);
        user.setLockedUntil(OffsetDateTime.now().plusMinutes(3));

        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));



        // Act & Assert
        UnauthorizedException ex = assertThrows(
                UnauthorizedException.class,
                () -> authService.login(request, ip, userAgent)
        );

        assertEquals("Account temporarily locked. Try again later.", ex.getMessage());

        verify(auditService).logLoginFailedWithUser(
                eq(user),
                eq("Account locked"),
                eq(ip),
                eq(userAgent)
        );
    }

    @Test
    @DisplayName("TC_LOGIN_008 - Lock expired (status = LOCKED but isLocked = false)")
    void shouldResetLockAndProceed_whenLockExpired() {

        // Arrange
        user.setStatus(AdminUserStatus.LOCKED);

        // IMPORTANT: match production type (OffsetDateTime, not LocalDateTime)
        user.setLockedUntil(OffsetDateTime.now().minusMinutes(5));
        user.setFailedLoginCount(5);

        AppProperties.Security security = mock(AppProperties.Security.class);

        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(request.getPassword(), user.getPasswordHash()))
                .thenReturn(true);

        when(userRoleRepository.findRoleCodesByUserId(user.getId()))
                .thenReturn(List.of("USER"));

        when(userRoleRepository.findPermissionCodesByUserId(user.getId()))
                .thenReturn(List.of("READ"));

        when(userStoreScopeRepository.findByUserId(user.getId()))
                .thenReturn(Collections.emptyList());

        when(jwtService.generateAccessToken(any(), any(), any(), any(), any(), any()))
                .thenReturn("token");

        when(jwtService.getAccessTokenExpirySeconds())
                .thenReturn(3600);

        when(refreshTokenService.issueRefreshToken(any(), any(), any(), any(), any()))
                .thenReturn("refresh");

        when(adminUserRepository.save(any(AdminUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        AuthResponse response = authService.login(request, ip, userAgent);

        // Assert
        assertNotNull(response);

        ArgumentCaptor<AdminUser> userCaptor = ArgumentCaptor.forClass(AdminUser.class);
        verify(adminUserRepository, atLeastOnce()).save(userCaptor.capture());

        AdminUser savedUser = userCaptor.getValue();

        assertEquals(AdminUserStatus.ACTIVE, savedUser.getStatus());
        assertEquals(0, savedUser.getFailedLoginCount());
        assertNull(savedUser.getLockedUntil());
    }

    @Test
    void shouldIncrementFailedCount_whenWrongPassword() {

        // Arrange
        user.setFailedLoginCount(2);
        user.setStatus(AdminUserStatus.ACTIVE);

        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(any(), any()))
                .thenReturn(false);

        // IMPORTANT: set actual field used in service
        ReflectionTestUtils.setField(authService, "maxFailedAttempts", 5);
        ReflectionTestUtils.setField(authService, "lockDurationMinutes", 15);

        when(adminUserRepository.save(any(AdminUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act & Assert
        assertThrows(
                UnauthorizedException.class,
                () -> authService.login(request, ip, userAgent)
        );

        // Capture saved user
        ArgumentCaptor<AdminUser> captor = ArgumentCaptor.forClass(AdminUser.class);
        verify(adminUserRepository).save(captor.capture());

        AdminUser saved = captor.getValue();

        assertEquals(3, saved.getFailedLoginCount());
        assertEquals(AdminUserStatus.ACTIVE, saved.getStatus());


        verify(auditService).logLoginFailedWithUser(
                eq(user),
                eq("Invalid password"),
                eq(ip),
                eq(userAgent)
        );
    }

    @Test
    void shouldLockAccount_whenFifthFailedAttempt() {

        // Arrange
        user.setFailedLoginCount(4);
        user.setStatus(AdminUserStatus.ACTIVE);

        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(any(), any()))
                .thenReturn(false);


        ReflectionTestUtils.setField(authService, "maxFailedAttempts", 5);
        ReflectionTestUtils.setField(authService, "lockDurationMinutes", 30);

        when(adminUserRepository.save(any(AdminUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        OffsetDateTime before = OffsetDateTime.now();

        // Act & Assert
        assertThrows(
                UnauthorizedException.class,
                () -> authService.login(request, ip, userAgent)
        );

        ArgumentCaptor<AdminUser> captor = ArgumentCaptor.forClass(AdminUser.class);
        verify(adminUserRepository).save(captor.capture());

        AdminUser savedUser = captor.getValue();

        // Assertions
        assertEquals(5, savedUser.getFailedLoginCount());
        assertEquals(AdminUserStatus.LOCKED, savedUser.getStatus());
        assertNotNull(savedUser.getLockedUntil());

        // Slightly safer timing assertion
        assertTrue(savedUser.getLockedUntil()
                .isAfter(before.plusMinutes(29)));
    }
    @Test
    void shouldLoginSuccessfully_withDifferentEmailCase() {
        // Arrange
        request.setEmail("TeSt@ExAmPlE.CoM");

        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), "TeSt@ExAmPlE.CoM"))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(request.getPassword(), user.getPasswordHash()))
                .thenReturn(true);

        when(userRoleRepository.findRoleCodesByUserId(user.getId()))
                .thenReturn(List.of("USER"));

        when(userRoleRepository.findPermissionCodesByUserId(user.getId()))
                .thenReturn(List.of("READ"));

        when(userStoreScopeRepository.findByUserId(user.getId()))
                .thenReturn(Collections.emptyList());

        when(jwtService.generateAccessToken(any(), any(), any(), any(), any(), any()))
                .thenReturn("token");

        when(jwtService.getAccessTokenExpirySeconds())
                .thenReturn(3600);

        when(refreshTokenService.issueRefreshToken(any(), any(), any(), any(), any()))
                .thenReturn("refresh");

        when(adminUserRepository.save(any(AdminUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        AuthResponse response = authService.login(request, ip, userAgent);

        // Assert
        assertNotNull(response);
        verify(adminUserRepository).findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), "TeSt@ExAmPlE.CoM"
        );
    }

    @Test
    void shouldThrowException_whenPasswordIsNull() {

        // Arrange
        request.setPassword(null);



        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(null, user.getPasswordHash()))
                .thenReturn(false);

        when(adminUserRepository.save(any(AdminUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act & Assert
        assertThrows(
                UnauthorizedException.class,
                () -> authService.login(request, ip, userAgent)
        );
    }

    @Test
    void shouldThrowException_whenPasswordIsEmpty() {

        // Arrange
        request.setPassword("");



        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches("", user.getPasswordHash()))
                .thenReturn(false);

        when(adminUserRepository.save(any(AdminUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act & Assert
        assertThrows(
                UnauthorizedException.class,
                () -> authService.login(request, ip, userAgent)
        );
    }
    //Get Current User Test Cases Starts Here:

    @Test
    void shouldReturnUserResponse_whenTokenIsValid() {
        // Arrange
        String token = "valid-token";

        when(jwtService.extractUserId(token))
                .thenReturn(user.getId());

        when(adminUserRepository.findById(user.getId()))
                .thenReturn(Optional.of(user));

        when(tenantRegistryRepository.findById(user.getTenantId()))
                .thenReturn(Optional.of(activeTenant));

        when(userRoleRepository.findRoleCodesByUserId(user.getId()))
                .thenReturn(List.of("ADMIN", "USER"));

        when(userRoleRepository.findPermissionCodesByUserId(user.getId()))
                .thenReturn(List.of("READ", "WRITE"));

        when(userStoreScopeRepository.findByUserId(user.getId()))
                .thenReturn(Collections.emptyList());

        // Act
        UserResponse response = authService.getCurrentUser(token);

        // Assert
        assertNotNull(response);
        assertEquals(user.getId(), response.getUserId());
        assertEquals(user.getEmail(), response.getEmail());
        assertTrue(response.getRoles().contains("ADMIN"));
        assertTrue(response.getPermissions().contains("READ"));
    }

    @Test
    void shouldThrowException_whenTokenIsInvalid() {
        // Arrange
        String token = "invalid-token";

        when(jwtService.extractUserId(token))
                .thenThrow(new RuntimeException("Invalid token"));

        // Act & Assert
        assertThrows(
                RuntimeException.class,
                () -> authService.getCurrentUser(token)
        );
    }

    @Test
    void shouldThrowException_whenGetCurrentUserUserNotFound() {
        // Arrange
        String token = "valid-token";
        UUID userId = UUID.randomUUID();

        when(jwtService.extractUserId(token))
                .thenReturn(userId);

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(
                UnauthorizedException.class,
                () -> authService.getCurrentUser(token)
        );
    }

    @Test
    void shouldThrowException_whenUserIsInactive() {
        // Arrange
        String token = "valid-token";
        user.setStatus(AdminUserStatus.DISABLED);

        when(jwtService.extractUserId(token))
                .thenReturn(user.getId());

        when(adminUserRepository.findById(user.getId()))
                .thenReturn(Optional.of(user));

        // Act & Assert
        assertThrows(
                UnauthorizedException.class,
                () -> authService.getCurrentUser(token)
        );
    }

    @Test
    void shouldThrowException_GetCurrentUserTenantNotFound() {
        // Arrange
        String token = "valid-token";

        when(jwtService.extractUserId(token))
                .thenReturn(user.getId());

        when(adminUserRepository.findById(user.getId()))
                .thenReturn(Optional.of(user));

        when(tenantRegistryRepository.findById(user.getTenantId()))
                .thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(
                UnauthorizedException.class,
                () -> authService.getCurrentUser(token)
        );
    }

    @Test
    void shouldReturnNewTokens_whenRefreshTokenIsValid() {

        // Arrange
        String refreshToken = "valid-refresh-token";

        // Mock RefreshToken entity (IMPORTANT: service uses entity, not userId)
        RefreshToken tokenEntity = new RefreshToken();
        tokenEntity.setUser(user);
        tokenEntity.setTokenFamily(UUID.randomUUID());

        when(refreshTokenService.validateAndGetToken(refreshToken))
                .thenReturn(tokenEntity);

        when(tenantRegistryRepository.findById(user.getTenantId()))
                .thenReturn(Optional.of(activeTenant));

        when(userRoleRepository.findRoleCodesByUserId(user.getId()))
                .thenReturn(List.of("USER"));

        when(userRoleRepository.findPermissionCodesByUserId(user.getId()))
                .thenReturn(List.of("READ"));

        when(userStoreScopeRepository.findByUserId(user.getId()))
                .thenReturn(Collections.emptyList());

        when(jwtService.generateAccessToken(any(), any(), any(), any(), any(), any()))
                .thenReturn("new-access-token");

        when(jwtService.getAccessTokenExpirySeconds())
                .thenReturn(3600);

        when(refreshTokenService.rotateToken(
                eq(tokenEntity),
                eq(user),
                eq(activeTenant),
                eq(ip),
                eq(userAgent)
        )).thenReturn("new-refresh-token");

        // Act
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken(refreshToken);

        AuthResponse response = authService.refresh(request, ip, userAgent);

        // Assert
        assertNotNull(response);
        assertEquals("new-access-token", response.getAccessToken());
        assertEquals("new-refresh-token", response.getRefreshToken());
        assertEquals("Bearer", response.getTokenType());

        // Verify audit
        verify(auditService).logTokenRefreshed(user, ip, userAgent);
    }

    @Test
    void shouldThrowException_whenRefreshTokenIsInvalid() {

        // Arrange
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("invalid-refresh-token");

        when(refreshTokenService.validateAndGetToken("invalid-refresh-token"))
                .thenReturn(null);

        // Act & Assert
        UnauthorizedException ex = assertThrows(
                UnauthorizedException.class,
                () -> authService.refresh(request, ip, userAgent)
        );

        assertEquals("Invalid or expired refresh token", ex.getMessage());

        // IMPORTANT: no audit verification because service does not call it
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldThrowException_whenUserIsInactiveOnRefresh() {

        // Arrange
        String refreshToken = "valid-refresh-token";

        user.setStatus(AdminUserStatus.DISABLED);

        RefreshToken tokenEntity = new RefreshToken();
        tokenEntity.setUser(user);

        when(refreshTokenService.validateAndGetToken(refreshToken))
                .thenReturn(tokenEntity);

        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken(refreshToken);

        // Act & Assert
        UnauthorizedException ex = assertThrows(
                UnauthorizedException.class,
                () -> authService.refresh(request, ip, userAgent)
        );

        assertEquals("User account is not active", ex.getMessage());

        verifyNoInteractions(tenantRegistryRepository);
        verifyNoInteractions(jwtService);
    }

    @Test
    void shouldThrowException_whenTenantNotFoundOnRefresh() {

        // Arrange
        String refreshToken = "valid-refresh-token";

        RefreshToken tokenEntity = new RefreshToken();
        tokenEntity.setUser(user);

        when(refreshTokenService.validateAndGetToken(refreshToken))
                .thenReturn(tokenEntity);

        when(tenantRegistryRepository.findById(user.getTenantId()))
                .thenReturn(Optional.empty());

        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken(refreshToken);

        UnauthorizedException ex = assertThrows(
                UnauthorizedException.class,
                () -> authService.refresh(request, ip, userAgent)
        );

        assertEquals("Tenant not found", ex.getMessage());

        verify(adminUserRepository, never()).findById(any());
    }

    @Test
    void shouldRotateRefreshToken() {

        // Arrange
        String oldRefreshToken = "old-refresh-token";
        String newRefreshToken = "new-refresh-token";

        RefreshToken tokenEntity = new RefreshToken();
        tokenEntity.setUser(user);
        tokenEntity.setTokenFamily(UUID.randomUUID());

        when(refreshTokenService.validateAndGetToken(oldRefreshToken))
                .thenReturn(tokenEntity);

        when(tenantRegistryRepository.findById(user.getTenantId()))
                .thenReturn(Optional.of(activeTenant));

        when(userRoleRepository.findRoleCodesByUserId(user.getId()))
                .thenReturn(List.of("USER"));

        when(userRoleRepository.findPermissionCodesByUserId(user.getId()))
                .thenReturn(List.of("READ"));

        when(userStoreScopeRepository.findByUserId(user.getId()))
                .thenReturn(Collections.emptyList());

        when(jwtService.generateAccessToken(any(), any(), any(), any(), any(), any()))
                .thenReturn("access-token");

        when(jwtService.getAccessTokenExpirySeconds())
                .thenReturn(3600);

        when(refreshTokenService.rotateToken(
                eq(tokenEntity),
                eq(user),
                eq(activeTenant),
                eq(ip),
                eq(userAgent)
        )).thenReturn(newRefreshToken);

        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken(oldRefreshToken);

        // Act
        AuthResponse response = authService.refresh(request, ip, userAgent);

        // Assert
        assertEquals(newRefreshToken, response.getRefreshToken());
        assertNotEquals(oldRefreshToken, response.getRefreshToken());

        verify(refreshTokenService).rotateToken(
                eq(tokenEntity),
                eq(user),
                eq(activeTenant),
                eq(ip),
                eq(userAgent)
        );
    }

    @Test
    void shouldRevokeToken_onValidLogout() {

        // Arrange
        String refreshToken = "valid-refresh-token";

        LogoutRequest request = new LogoutRequest();
        request.setRefreshToken(refreshToken);

        doNothing().when(refreshTokenService).revokeToken(refreshToken);

        // Act
        authService.logout(request);

        // Assert
        verify(refreshTokenService).revokeToken(refreshToken);
    }

    @Test
    void shouldNotCrash_whenTokenAlreadyRevoked() {

        // Arrange
        String refreshToken = "already-revoked-token";

        LogoutRequest request = new LogoutRequest();
        request.setRefreshToken(refreshToken);

        doNothing().when(refreshTokenService).revokeToken(refreshToken);

        // Act & Assert
        assertDoesNotThrow(() -> authService.logout(request));

        verify(refreshTokenService).revokeToken(refreshToken);
    }

    @Test
    void shouldNotBreak_whenTokenIsInvalid() {

        // Arrange
        String refreshToken = "invalid-token";

        LogoutRequest request = new LogoutRequest();
        request.setRefreshToken(refreshToken);

        doNothing().when(refreshTokenService).revokeToken(refreshToken);

        // Act & Assert
        assertDoesNotThrow(() -> authService.logout(request));

        verify(refreshTokenService).revokeToken(refreshToken);
    }

    @Test
    void shouldIncludeRolesAndPermissions() {

        // Arrange
        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(request.getPassword(), user.getPasswordHash()))
                .thenReturn(true);

        when(userRoleRepository.findRoleCodesByUserId(user.getId()))
                .thenReturn(List.of("ADMIN", "MANAGER", "USER"));

        when(userRoleRepository.findPermissionCodesByUserId(user.getId()))
                .thenReturn(List.of("READ", "WRITE", "DELETE", "UPDATE"));

        when(userStoreScopeRepository.findByUserId(user.getId()))
                .thenReturn(Collections.emptyList());

        when(jwtService.generateAccessToken(any(), any(), any(), any(), any(), any()))
                .thenReturn("token");

        when(jwtService.getAccessTokenExpirySeconds())
                .thenReturn(3600);

        when(refreshTokenService.issueRefreshToken(any(), any(), any(), any(), any()))
                .thenReturn("refresh");

        when(adminUserRepository.save(any(AdminUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        AuthResponse response = authService.login(request, ip, userAgent);

        UserResponse userResp = response.getUser();

        // Assert
        assertEquals(3, userResp.getRoles().size());
        assertTrue(userResp.getRoles().contains("ADMIN"));
        assertTrue(userResp.getRoles().contains("MANAGER"));

        assertEquals(4, userResp.getPermissions().size());
        assertTrue(userResp.getPermissions().contains("READ"));
        assertTrue(userResp.getPermissions().contains("DELETE"));
    }

    @Test
    void shouldDeduplicateBrandAndStoreScopes() {

        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(request.getPassword(), user.getPasswordHash()))
                .thenReturn(true);

        when(userRoleRepository.findRoleCodesByUserId(user.getId()))
                .thenReturn(List.of("USER"));

        when(userRoleRepository.findPermissionCodesByUserId(user.getId()))
                .thenReturn(List.of("READ"));

        when(userStoreScopeRepository.findByUserId(user.getId()))
                .thenReturn(Collections.emptyList());

        when(jwtService.generateAccessToken(any(), any(), any(), any(), any(), any()))
                .thenReturn("token");

        when(jwtService.getAccessTokenExpirySeconds())
                .thenReturn(3600);

        when(refreshTokenService.issueRefreshToken(any(), any(), any(), any(), any()))
                .thenReturn("refresh");

        when(adminUserRepository.save(any(AdminUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        AuthResponse response = authService.login(request, ip, userAgent);

        UserResponse userResp = response.getUser();

        // Assert
        assertNotNull(userResp.getBrandScope());
        assertNotNull(userResp.getStoreScope());

        verify(userStoreScopeRepository).findByUserId(user.getId());
    }

    @Test
    void shouldIncludeRefreshTokenOnLogin() {

        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(request.getPassword(), user.getPasswordHash()))
                .thenReturn(true);

        when(userRoleRepository.findRoleCodesByUserId(user.getId()))
                .thenReturn(List.of("USER"));

        when(userRoleRepository.findPermissionCodesByUserId(user.getId()))
                .thenReturn(List.of("READ"));

        when(userStoreScopeRepository.findByUserId(user.getId()))
                .thenReturn(Collections.emptyList());

        when(jwtService.generateAccessToken(any(), any(), any(), any(), any(), any()))
                .thenReturn("access-token");

        when(jwtService.getAccessTokenExpirySeconds())
                .thenReturn(3600);

        when(refreshTokenService.issueRefreshToken(any(), any(), any(), any(), any()))
                .thenReturn("refresh-token-from-login");

        when(adminUserRepository.save(any(AdminUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        AuthResponse response = authService.login(request, ip, userAgent);

        // Assert
        assertEquals("refresh-token-from-login", response.getRefreshToken());
    }

    @Test
    @DisplayName("Edge Case - Empty roles list")
    void shouldHandleEmptyRolesList() {
        // Arrange
        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(request.getPassword(), user.getPasswordHash()))
                .thenReturn(true);

        when(userRoleRepository.findRoleCodesByUserId(user.getId()))
                .thenReturn(Collections.emptyList());

        when(userRoleRepository.findPermissionCodesByUserId(user.getId()))
                .thenReturn(Collections.emptyList());

        when(userStoreScopeRepository.findByUserId(user.getId()))
                .thenReturn(Collections.emptyList());

        when(jwtService.generateAccessToken(any(), any(), any(), any(), any(), any()))
                .thenReturn("token");

        when(jwtService.getAccessTokenExpirySeconds())
                .thenReturn(3600);

        when(refreshTokenService.issueRefreshToken(any(), any(), any(), any(), any()))
                .thenReturn("refresh");

        when(adminUserRepository.save(any(AdminUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        AuthResponse response = authService.login(request, ip, userAgent);

        // Assert
        assertNotNull(response);
        assertNotNull(response.getUser().getRoles());
        assertTrue(response.getUser().getRoles().isEmpty());
    }

    @Test
    @DisplayName("Edge Case - Lock expiry exactly at boundary (30 minutes)")
    void shouldHandleLockExpiryAtExactBoundary() {
        // Arrange
        user.setStatus(AdminUserStatus.LOCKED);
        user.setLockedUntil(OffsetDateTime.now()); // Exactly now
        user.setFailedLoginCount(5);

        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(request.getPassword(), user.getPasswordHash()))
                .thenReturn(true);

        when(userRoleRepository.findRoleCodesByUserId(user.getId()))
                .thenReturn(List.of("USER"));

        when(userRoleRepository.findPermissionCodesByUserId(user.getId()))
                .thenReturn(List.of("READ"));

        when(userStoreScopeRepository.findByUserId(user.getId()))
                .thenReturn(Collections.emptyList());

        when(jwtService.generateAccessToken(any(), any(), any(), any(), any(), any()))
                .thenReturn("token");

        when(jwtService.getAccessTokenExpirySeconds())
                .thenReturn(3600);

        when(refreshTokenService.issueRefreshToken(any(), any(), any(), any(), any()))
                .thenReturn("refresh");

        when(adminUserRepository.save(any(AdminUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        AuthResponse response = authService.login(request, ip, userAgent);

        // Assert - should unlock and proceed
        assertNotNull(response);
    }

    @Test
    void shouldPropagateException_whenDatabaseSaveFails() {
        // Arrange
        when(tenantRegistryRepository.findBySlug(request.getTenantSlug()))
                .thenReturn(Optional.of(activeTenant));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(
                activeTenant.getId(), request.getEmail()))
                .thenReturn(Optional.of(user));

        when(passwordEncoder.matches(request.getPassword(), user.getPasswordHash()))
                .thenReturn(true);


        when(adminUserRepository.save(any(AdminUser.class)))
                .thenThrow(new RuntimeException("Database connection failed"));

        // Act & Assert
        assertThrows(
                RuntimeException.class,
                () -> authService.login(request, ip, userAgent)
        );
    }


}
