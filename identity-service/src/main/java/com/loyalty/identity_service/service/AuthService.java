package com.loyalty.identity_service.service;

import com.loyalty.identity_service.dto.*;

public interface AuthService {

    public AuthResponse login(LoginRequest request, String ipAddress, String userAgent);

    public UserResponse getCurrentUser(String token);

    public AuthResponse refresh(RefreshRequest request, String ipAddress, String userAgent);

    public void logout(LogoutRequest request);
}
