package com.loyalty.identity_service.controller;

import com.loyalty.identity_service.dto.AuthResponse;
import com.loyalty.identity_service.dto.LoginRequest;
import com.loyalty.identity_service.dto.RefreshRequest;
import com.loyalty.identity_service.dto.UserResponse;
import com.loyalty.identity_service.exception.ForbiddenException;
import com.loyalty.identity_service.exception.GlobalExceptionHandler;
import com.loyalty.identity_service.exception.ResourceNotFoundException;
import com.loyalty.identity_service.exception.UnauthorizedException;
import com.loyalty.identity_service.service.AuthService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@WebMvcTest(AuthController.class)
@Import(GlobalExceptionHandler.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    private AuthResponse sampleAuthResponse() {
        return AuthResponse.builder()
                .accessToken("access-token")
                .refreshToken("refresh-token")
                .tokenType("Bearer")
                .expiresIn(900)
                .user(UserResponse.builder()
                        .email("john@acme.com")
                        .roles(List.of("TENANT_OWNER"))
                        .build())
                .build();
    }

    // ================= LOGIN =================

    @Test
    @WithMockUser
    void shouldReturn200WhenLoginIsValid() throws Exception {
        when(authService.login(
                any(LoginRequest.class),
                nullable(String.class),
                nullable(String.class)
        )).thenReturn(sampleAuthResponse());

        mockMvc.perform(post("/auth/admin/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                            {"tenantSlug":"acme","email":"john@acme.com","password":"pass"}
                        """)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.access_token").isNotEmpty())
                .andExpect(jsonPath("$.data.refresh_token").isNotEmpty());
    }

    @Test
    @WithMockUser
    void shouldReturn401WhenLoginFails() throws Exception {
        when(authService.login(
                any(LoginRequest.class),
                nullable(String.class),
                nullable(String.class)
        )).thenThrow(new UnauthorizedException("Invalid credentials"));

        mockMvc.perform(post("/auth/admin/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                            {"tenantSlug":"acme","email":"john@acme.com","password":"wrong"}
                        """)
                        .with(csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("INVALID_CREDENTIALS"));
    }

    @Test
    @WithMockUser
    void shouldReturn400WhenLoginRequestIsInvalid() throws Exception {
        mockMvc.perform(post("/auth/admin/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
                        .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
    }

    // ================= GET CURRENT USER =================

    @Test
    @WithMockUser
    void shouldReturn200WhenValidTokenProvided() throws Exception {
        when(authService.getCurrentUser(anyString()))
                .thenReturn(sampleAuthResponse().getUser());

        mockMvc.perform(get("/auth/me")
                        .header("Authorization", "Bearer valid.token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.email").value("john@acme.com"));
    }

    @Test
    @WithMockUser
    void shouldReturn401WhenTokenIsInvalid() throws Exception {
        when(authService.getCurrentUser(anyString()))
                .thenThrow(new UnauthorizedException("Invalid token"));

        mockMvc.perform(get("/auth/me")
                        .header("Authorization", "Bearer bad.token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("INVALID_CREDENTIALS"));
    }

    @Test
    @WithMockUser
    void shouldReturn400WhenAuthorizationHeaderMissing() throws Exception {
        mockMvc.perform(get("/auth/me"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("MISSING_HEADER"));
    }

    @Test
    @WithMockUser
    void shouldReturn401WhenAuthorizationHeaderMalformed() throws Exception {
        mockMvc.perform(get("/auth/me")
                        .header("Authorization", "InvalidHeader"))
                .andExpect(status().isUnauthorized());
    }

    // ================= REFRESH TOKEN =================

    @Test
    @WithMockUser
    void shouldReturn200WhenRefreshTokenIsValid() throws Exception {
        when(authService.refresh(
                any(RefreshRequest.class),
                nullable(String.class),
                nullable(String.class)
        )).thenReturn(sampleAuthResponse());

        mockMvc.perform(post("/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"valid-token\"}")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.access_token").isNotEmpty());
    }

    @Test
    @WithMockUser
    void shouldReturn401WhenRefreshTokenIsInvalid() throws Exception {
        when(authService.refresh(
                any(RefreshRequest.class),
                nullable(String.class),
                nullable(String.class)
        )).thenThrow(new UnauthorizedException("Invalid"));

        mockMvc.perform(post("/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"bad-token\"}")
                        .with(csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("INVALID_CREDENTIALS"));
    }

    @Test
    @WithMockUser
    void shouldReturn400WhenRefreshTokenMissing() throws Exception {
        mockMvc.perform(post("/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    void shouldReturn400WhenRefreshTokenEmpty() throws Exception {
        mockMvc.perform(post("/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"\"}")
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    // ================= LOGOUT =================

    @Test
    @WithMockUser
    void shouldReturn200WhenLogoutIsSuccessful() throws Exception {
        doNothing().when(authService).logout(any());

        mockMvc.perform(post("/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"token\"}")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    @WithMockUser
    void shouldReturn400WhenLogoutRequestIsInvalid() throws Exception {
        mockMvc.perform(post("/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    // ================= GLOBAL EXCEPTION =================

    @Test
    @WithMockUser
    void shouldReturn403WhenForbiddenExceptionOccurs() throws Exception {
        when(authService.getCurrentUser(anyString()))
                .thenThrow(new ForbiddenException("Access denied"));

        mockMvc.perform(get("/auth/me")
                        .header("Authorization", "Bearer token"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("FORBIDDEN"));
    }

    @Test
    @WithMockUser
    void shouldReturn404WhenResourceNotFound() throws Exception {
        when(authService.getCurrentUser(anyString()))
                .thenThrow(new ResourceNotFoundException("Not found"));

        mockMvc.perform(get("/auth/me")
                        .header("Authorization", "Bearer token"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("NOT_FOUND"));
    }

    @Test
    @WithMockUser
    void shouldReturn500WhenUnexpectedErrorOccurs() throws Exception {
        when(authService.login(
                any(LoginRequest.class),
                nullable(String.class),
                nullable(String.class)
        )).thenThrow(new RuntimeException("error"));

        mockMvc.perform(post("/auth/admin/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"tenantSlug":"acme","email":"john@acme.com","password":"pass"}
                    """)
                        .with(csrf()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error.code").value("INTERNAL_ERROR"));
    }
}
