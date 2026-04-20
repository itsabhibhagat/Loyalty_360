package com.loyalty.identity_service.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class CreateAdminUserResponse extends UserResponse {
    private String temporaryPassword;
}
