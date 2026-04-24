package com.loyalty.identity_service.service.impl;

import com.loyalty.identity_service.entity.AdminUser;
import com.loyalty.identity_service.entity.AuthAuditLog;
import com.loyalty.identity_service.repository.AuthAuditLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuditServiceImpl Tests")
class AuditServiceImplTest {

    @Mock
    private AuthAuditLogRepository auditLogRepository;

    @InjectMocks
    private AuditServiceImpl auditService;

    @Captor
    private ArgumentCaptor<AuthAuditLog> auditLogCaptor;

    private UUID tenantId;
    private UUID userId;
    private AdminUser adminUser;
    private String ipAddress;
    private String userAgent;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        userId = UUID.randomUUID();
        ipAddress = "192.168.1.100";
        userAgent = "Mozilla/5.0";

        adminUser = AdminUser.builder()
                .id(userId)
                .tenantId(tenantId)
                .email("admin@example.com")
                .build();
    }

    @Test
    @DisplayName("Should log successful login with correct details")
    void logLoginSuccess_ShouldCreateCorrectAuditLog() {
        // When
        auditService.logLoginSuccess(adminUser, ipAddress, userAgent);

        // Then
        verify(auditLogRepository).save(auditLogCaptor.capture());
        AuthAuditLog captured = auditLogCaptor.getValue();

        assertThat(captured.getTenantId()).isEqualTo(tenantId);
        assertThat(captured.getActorType()).isEqualTo("ADMIN_USER");
        assertThat(captured.getActorId()).isEqualTo(userId);
        assertThat(captured.getActorEmail()).isEqualTo("admin@example.com");
        assertThat(captured.getEventType()).isEqualTo("LOGIN_SUCCESS");
        assertThat(captured.getSuccess()).isTrue();
        assertThat(captured.getFailureReason()).isNull();
        assertThat(captured.getIpAddress()).isEqualTo(ipAddress);
        assertThat(captured.getUserAgent()).isEqualTo(userAgent);
    }

    @Test
    @DisplayName("Should log failed login without user object")
    void logLoginFailed_ShouldCreateCorrectAuditLog() {
        // Given
        String email = "unknown@example.com";
        String reason = "Invalid credentials";

        // When
        auditService.logLoginFailed(tenantId, email, reason, ipAddress, userAgent);

        // Then
        verify(auditLogRepository).save(auditLogCaptor.capture());
        AuthAuditLog captured = auditLogCaptor.getValue();

        assertThat(captured.getTenantId()).isEqualTo(tenantId);
        assertThat(captured.getActorType()).isEqualTo("ADMIN_USER");
        assertThat(captured.getActorId()).isNull();
        assertThat(captured.getActorEmail()).isEqualTo(email);
        assertThat(captured.getEventType()).isEqualTo("LOGIN_FAILED");
        assertThat(captured.getSuccess()).isFalse();
        assertThat(captured.getFailureReason()).isEqualTo(reason);
        assertThat(captured.getIpAddress()).isEqualTo(ipAddress);
        assertThat(captured.getUserAgent()).isEqualTo(userAgent);
    }

    @Test
    @DisplayName("Should log failed login with user object")
    void logLoginFailedWithUser_ShouldCreateCorrectAuditLog() {
        // Given
        String reason = "Account locked";

        // When
        auditService.logLoginFailedWithUser(adminUser, reason, ipAddress, userAgent);

        // Then
        verify(auditLogRepository).save(auditLogCaptor.capture());
        AuthAuditLog captured = auditLogCaptor.getValue();

        assertThat(captured.getTenantId()).isEqualTo(tenantId);
        assertThat(captured.getActorType()).isEqualTo("ADMIN_USER");
        assertThat(captured.getActorId()).isEqualTo(userId);
        assertThat(captured.getActorEmail()).isEqualTo("admin@example.com");
        assertThat(captured.getEventType()).isEqualTo("LOGIN_FAILED");
        assertThat(captured.getSuccess()).isFalse();
        assertThat(captured.getFailureReason()).isEqualTo(reason);
        assertThat(captured.getIpAddress()).isEqualTo(ipAddress);
        assertThat(captured.getUserAgent()).isEqualTo(userAgent);
    }

    @Test
    @DisplayName("Should log token refresh event")
    void logTokenRefreshed_ShouldCreateCorrectAuditLog() {
        // When
        auditService.logTokenRefreshed(adminUser, ipAddress, userAgent);

        // Then
        verify(auditLogRepository).save(auditLogCaptor.capture());
        AuthAuditLog captured = auditLogCaptor.getValue();

        assertThat(captured.getTenantId()).isEqualTo(tenantId);
        assertThat(captured.getActorType()).isEqualTo("ADMIN_USER");
        assertThat(captured.getActorId()).isEqualTo(userId);
        assertThat(captured.getActorEmail()).isEqualTo("admin@example.com");
        assertThat(captured.getEventType()).isEqualTo("TOKEN_REFRESHED");
        assertThat(captured.getSuccess()).isTrue();
        assertThat(captured.getFailureReason()).isNull();
        assertThat(captured.getIpAddress()).isEqualTo(ipAddress);
        assertThat(captured.getUserAgent()).isEqualTo(userAgent);
    }

    @Test
    @DisplayName("Should log user creation event")
    void logUserCreated_ShouldCreateCorrectAuditLog() {
        // Given
        UUID createdUserId = UUID.randomUUID();

        // When
        auditService.logUserCreated(tenantId, userId, createdUserId);

        // Then
        verify(auditLogRepository).save(auditLogCaptor.capture());
        AuthAuditLog captured = auditLogCaptor.getValue();

        assertThat(captured.getTenantId()).isEqualTo(tenantId);
        assertThat(captured.getActorType()).isEqualTo("ADMIN_USER");
        assertThat(captured.getActorId()).isEqualTo(userId);
        assertThat(captured.getActorEmail()).isNull();
        assertThat(captured.getEventType()).isEqualTo("USER_CREATED");
        assertThat(captured.getSuccess()).isTrue();
        assertThat(captured.getFailureReason()).isNull();
        assertThat(captured.getIpAddress()).isNull();
        assertThat(captured.getUserAgent()).isNull();
    }

    @Test
    @DisplayName("Should log user deactivation event")
    void logUserDeactivated_ShouldCreateCorrectAuditLog() {
        // Given
        UUID targetUserId = UUID.randomUUID();

        // When
        auditService.logUserDeactivated(tenantId, userId, targetUserId);

        // Then
        verify(auditLogRepository).save(auditLogCaptor.capture());
        AuthAuditLog captured = auditLogCaptor.getValue();

        assertThat(captured.getTenantId()).isEqualTo(tenantId);
        assertThat(captured.getActorType()).isEqualTo("ADMIN_USER");
        assertThat(captured.getActorId()).isEqualTo(userId);
        assertThat(captured.getEventType()).isEqualTo("USER_DEACTIVATED");
        assertThat(captured.getSuccess()).isTrue();
        assertThat(captured.getFailureReason()).isNull();
    }

    @Test
    @DisplayName("Should log roles assignment event")
    void logRolesAssigned_ShouldCreateCorrectAuditLog() {
        // Given
        UUID targetUserId = UUID.randomUUID();

        // When
        auditService.logRolesAssigned(tenantId, userId, targetUserId);

        // Then
        verify(auditLogRepository).save(auditLogCaptor.capture());
        AuthAuditLog captured = auditLogCaptor.getValue();

        assertThat(captured.getTenantId()).isEqualTo(tenantId);
        assertThat(captured.getActorType()).isEqualTo("ADMIN_USER");
        assertThat(captured.getActorId()).isEqualTo(userId);
        assertThat(captured.getEventType()).isEqualTo("ROLES_ASSIGNED");
        assertThat(captured.getSuccess()).isTrue();
    }

    @Test
    @DisplayName("Should log store scopes assignment event")
    void logStoreScopesAssigned_ShouldCreateCorrectAuditLog() {
        // Given
        UUID targetUserId = UUID.randomUUID();

        // When
        auditService.logStoreScopesAssigned(tenantId, userId, targetUserId);

        // Then
        verify(auditLogRepository).save(auditLogCaptor.capture());
        AuthAuditLog captured = auditLogCaptor.getValue();

        assertThat(captured.getTenantId()).isEqualTo(tenantId);
        assertThat(captured.getActorType()).isEqualTo("ADMIN_USER");
        assertThat(captured.getActorId()).isEqualTo(userId);
        assertThat(captured.getEventType()).isEqualTo("STORE_SCOPES_ASSIGNED");
        assertThat(captured.getSuccess()).isTrue();
    }

    @Test
    @DisplayName("Should handle null IP address and user agent gracefully")
    void logLoginSuccess_WithNullIpAndUserAgent_ShouldCreateAuditLog() {
        // When
        auditService.logLoginSuccess(adminUser, null, null);

        // Then
        verify(auditLogRepository).save(auditLogCaptor.capture());
        AuthAuditLog captured = auditLogCaptor.getValue();

        assertThat(captured.getIpAddress()).isNull();
        assertThat(captured.getUserAgent()).isNull();
        assertThat(captured.getEventType()).isEqualTo("LOGIN_SUCCESS");
    }

    @Test
    @DisplayName("Should save audit log exactly once per method call")
    void allMethods_ShouldCallRepositorySaveOnce() {
        // When
        auditService.logLoginSuccess(adminUser, ipAddress, userAgent);

        // Then
        verify(auditLogRepository, times(1)).save(any(AuthAuditLog.class));
    }

    @Test
    @DisplayName("Should handle different failure reasons correctly")
    void logLoginFailed_WithDifferentReasons_ShouldLogCorrectly() {
        // Given
        String[] reasons = {
                "Invalid credentials",
                "Account locked",
                "Account expired",
                "Too many attempts",
                null
        };

        // When & Then
        for (String reason : reasons) {
            reset(auditLogRepository);
            auditService.logLoginFailed(tenantId, "test@example.com", reason, ipAddress, userAgent);

            verify(auditLogRepository).save(auditLogCaptor.capture());
            assertThat(auditLogCaptor.getValue().getFailureReason()).isEqualTo(reason);
        }
    }
}