package com.loyalty.identity_service.service;

import com.loyalty.identity_service.entity.AdminUser;
import com.loyalty.identity_service.entity.RefreshToken;
import com.loyalty.identity_service.entity.TenantRegistry;

import java.util.UUID;

public interface RefreshTokenService {

    public String issueRefreshToken(AdminUser user, TenantRegistry tenant,
                                    UUID tokenFamily, String ipAddress, String userAgent);

    public RefreshToken validateAndGetToken(String rawToken);

    public String rotateToken(RefreshToken oldToken, AdminUser user, TenantRegistry tenant,
                              String ipAddress, String userAgent);

    public void revokeToken(String rawToken);


}
