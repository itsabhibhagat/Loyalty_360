package com.loyalty.identity_service.controller;

import com.loyalty.identity_service.dto.*;
import com.loyalty.identity_service.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * POST /auth/admin/login
     * Authenticates admin user with tenant_slug + email + password.
     * Returns access_token (RS256 JWT) + refresh_token.
     */
    @PostMapping("/admin/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        String ip = getClientIp(httpRequest);
        String ua = httpRequest.getHeader(HttpHeaders.USER_AGENT);
        AuthResponse response = authService.login(request, ip, ua);
        return ResponseEntity.ok(ApiResponse.ok(response));
    }

    /**
     * POST /auth/token/refresh
     * Rotates the refresh token and issues a new access_token.
     * Implements theft detection via token families.
     */
    @PostMapping("/token/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(
            @Valid @RequestBody RefreshRequest request,
            HttpServletRequest httpRequest) {
        String ip = getClientIp(httpRequest);
        String ua = httpRequest.getHeader(HttpHeaders.USER_AGENT);
        AuthResponse response = authService.refresh(request, ip, ua);
        return ResponseEntity.ok(ApiResponse.ok(response));
    }

    /**
     * POST /auth/logout
     * Revokes the provided refresh token.
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @Valid @RequestBody LogoutRequest request) {
        authService.logout(request);
        return ResponseEntity.ok(ApiResponse.ok(null));
    }

    /**
     * GET /auth/me
     * Returns the current user profile from the JWT subject claim.
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> me(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new com.loyalty.identity_service.exception.UnauthorizedException(
                    "Missing or invalid Authorization header");
        }
        String token = authHeader.substring(7);
        UserResponse user = authService.getCurrentUser(token);
        return ResponseEntity.ok(ApiResponse.ok(user));
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}
