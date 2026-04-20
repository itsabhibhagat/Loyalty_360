package com.loyalty.identity_service.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LogoutRequest {
    @NotBlank(message = "refresh_token is required")
    private String refreshToken;

    public String getRefreshToken() {
    }
}
