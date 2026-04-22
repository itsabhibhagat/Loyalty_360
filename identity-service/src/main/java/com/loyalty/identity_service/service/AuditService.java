package com.loyalty.identity_service.service;

import com.loyalty.identity_service.entity.AdminUser;

import java.util.UUID;

public interface AuditService {

    public void logLoginSuccess(AdminUser user, String ipAddress, String userAgent);

    public void logLoginFailed(UUID tenantId, String email, String reason, String ipAddress, String userAgent);

    public void logLoginFailedWithUser(AdminUser user, String reason,String ipAddress, String userAgent);

    public void logTokenRefreshed(AdminUser user, String ipAddress, String userAgent);

    public void logUserCreated(UUID tenantId, UUID actorId, UUID createdUserId);

    public void logUserDeactivated(UUID tenantId, UUID actorId, UUID targetUserId);

    public void logRolesAssigned(UUID tenantId, UUID actorId, UUID targetUserId);

    public void logStoreScopesAssigned(UUID tenantId, UUID actorId, UUID targetUserId);


}
