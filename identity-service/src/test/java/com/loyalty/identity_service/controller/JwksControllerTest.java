package com.loyalty.identity_service.controller;

import com.loyalty.identity_service.config.JwtService;
import com.loyalty.identity_service.exception.ForbiddenException;
import com.loyalty.identity_service.exception.GlobalExceptionHandler;
import com.loyalty.identity_service.exception.ResourceNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@WebMvcTest(JwksController.class)
@Import(GlobalExceptionHandler.class)
@AutoConfigureMockMvc(addFilters = false)
class JwksControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtService jwtService;

    private Map<String, Object> sampleJwks() {
        return Map.of(
                "keys", List.of(
                        Map.of(
                                "kty", "RSA",
                                "kid", "key-id",
                                "use", "sig",
                                "alg", "RS256",
                                "n", "modulus",
                                "e", "AQAB"
                        )
                )
        );
    }

    // ================= GET JWKS =================

    @Test
    void shouldReturn200WhenJwksAvailable() throws Exception {
        when(jwtService.getJwks()).thenReturn(sampleJwks());

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kid").value("key-id"));
    }

    @Test
    void shouldReturnEmptyKeysWhenNoKeysAvailable() throws Exception {
        when(jwtService.getJwks()).thenReturn(Map.of("keys", List.of()));

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isEmpty());
    }

    // ================= ERROR HANDLING =================

    @Test
    void shouldReturn500WhenServiceFails() throws Exception {
        when(jwtService.getJwks())
                .thenThrow(new RuntimeException("error"));

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error.code").value("INTERNAL_ERROR"));
    }

    @Test
    void shouldReturn404WhenKeysNotFound() throws Exception {
        when(jwtService.getJwks())
                .thenThrow(new ResourceNotFoundException("No keys"));

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("NOT_FOUND"));
    }

    @Test
    void shouldReturn403WhenAccessForbidden() throws Exception {
        when(jwtService.getJwks())
                .thenThrow(new ForbiddenException("Forbidden"));

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("FORBIDDEN"));
    }
}
