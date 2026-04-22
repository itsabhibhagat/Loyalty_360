package com.loyalty.identity_service.service.impl;

import com.loyalty.identity_service.entity.AdminUser;
import com.loyalty.identity_service.entity.AuthAuditLog;
import com.loyalty.identity_service.repository.AuthAuditLogRepository;
import com.loyalty.identity_service.service.AuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditServiceImpl implements AuditService {

    private final AuthAuditLogRepository auditLogRepository;

    @Override
    public void logLoginSuccess(AdminUser user, String ipAddress, String userAgent) {
        log("LOGIN_SUCCESS", true, user.getTenantId(), user.getId(), user.getEmail(),
                null, ipAddress, userAgent);
    }

    @Override
    public void logLoginFailed(UUID tenantId, String email, String reason,
            String ipAddress, String userAgent) {
        log("LOGIN_FAILED", false, tenantId, null, email, reason, ipAddress, userAgent);
    }

    @Override
    public void logLoginFailedWithUser(AdminUser user, String reason,
            String ipAddress, String userAgent) {
        log("LOGIN_FAILED", false, user.getTenantId(), user.getId(), user.getEmail(),
                reason, ipAddress, userAgent);
    }
    @Override
    public void logTokenRefreshed(AdminUser user, String ipAddress, String userAgent) {
        log("TOKEN_REFRESHED", true, user.getTenantId(), user.getId(), user.getEmail(),
                null, ipAddress, userAgent);
    }
    @Override
    public void logUserCreated(UUID tenantId, UUID actorId, UUID createdUserId) {
        log("USER_CREATED", true, tenantId, actorId, null, null, null, null);
    }
    @Override
    public void logUserDeactivated(UUID tenantId, UUID actorId, UUID targetUserId) {
        log("USER_DEACTIVATED", true, tenantId, actorId, null, null, null, null);
    }
    @Override
    public void logRolesAssigned(UUID tenantId, UUID actorId, UUID targetUserId) {
        log("ROLES_ASSIGNED", true, tenantId, actorId, null, null, null, null);
    }
    @Override
    public void logStoreScopesAssigned(UUID tenantId, UUID actorId, UUID targetUserId) {
        log("STORE_SCOPES_ASSIGNED", true, tenantId, actorId, null, null, null, null);
    }

    private void log(String eventType, boolean success, UUID tenantId,
            UUID actorId, String actorEmail, String failureReason,
            String ipAddress, String userAgent) {
        AuthAuditLog entry = AuthAuditLog.builder()
                .tenantId(tenantId)
                .actorType("ADMIN_USER")
                .actorId(actorId)
                .actorEmail(actorEmail)
                .eventType(eventType)
                .success(success)
                .failureReason(failureReason)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();
        auditLogRepository.save(entry);
    }
}
