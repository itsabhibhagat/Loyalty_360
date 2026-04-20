package com.loyalty.identity_service.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserResponse {

    @JsonProperty("user_id")
    private UUID userId;

    @JsonProperty("tenant_id")
    private UUID tenantId;

    @JsonProperty("tenant_slug")
    private String tenantSlug;

    private String email;

    @JsonProperty("first_name")
    private String firstName;

    @JsonProperty("last_name")
    private String lastName;

    private String status;

    private List<String> roles;

    private List<String> permissions;

    @JsonProperty("brand_scope")
    private List<UUID> brandScope;

    @JsonProperty("store_scope")
    private List<UUID> storeScope;

    @JsonProperty("created_at")
    private Instant createdAt;

    @JsonProperty("temporary_password")
    private String temporaryPassword;
}
