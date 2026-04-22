package com.loyalty.identity_service.service;

import com.loyalty.identity_service.dto.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.UUID;

public interface AdminUserService {
    public Page<UserResponse> listUsers(UUID tenantId, String status, Pageable pageable);

    public CreateAdminUserResponse createUser(UUID tenantId, UUID callerId, CreateAdminUserRequest request);

    public UserResponse updateUser(UUID tenantId, UUID id, UpdateAdminUserRequest request);

    public void deactivateUser(UUID tenantId, UUID callerId, UUID id);

    public void assignRoles(UUID tenantId, UUID callerId, UUID id, AssignRolesRequest request);

    public void assignStoreScopes(UUID tenantId, UUID callerId, UUID id, AssignStoreScopesRequest request);
}
