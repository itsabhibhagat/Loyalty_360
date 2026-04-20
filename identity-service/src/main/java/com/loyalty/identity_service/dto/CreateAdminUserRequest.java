package com.loyalty.identity_service.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;
import java.util.UUID;

@Data
public class CreateAdminUserRequest {

    @NotBlank(message = "email is required")
    @Email(message = "email must be valid")
    private String email;

    @NotBlank(message = "first_name is required")
    @JsonProperty("first_name")
    private String firstName;

    @NotBlank(message = "last_name is required")
    @JsonProperty("last_name")
    private String lastName;

    @JsonProperty("role_codes")
    private List<String> roleCodes;

    @JsonProperty("brand_scope")
    private List<UUID> brandScope;

    @JsonProperty("store_scope")
    private List<UUID> storeScope;

    @JsonProperty("send_invite_email")
    private boolean sendInviteEmail;
}
