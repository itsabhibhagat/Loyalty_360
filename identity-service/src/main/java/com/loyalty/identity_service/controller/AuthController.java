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



    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}
