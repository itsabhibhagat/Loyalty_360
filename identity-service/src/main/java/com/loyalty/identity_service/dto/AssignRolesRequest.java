package com.loyalty.identity_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class AssignRolesRequest {
    @JsonProperty("role_codes")
    private List<String> roleCodes;
}
