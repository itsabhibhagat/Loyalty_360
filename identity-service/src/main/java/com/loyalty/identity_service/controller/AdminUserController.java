package com.loyalty.identity_service.controller;

import com.loyalty.identity_service.dto.*;
import com.loyalty.identity_service.service.AdminUserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/admin/users")
@RequiredArgsConstructor
public class AdminUserController {

    private final AdminUserService adminUserService;

    /**
     * POST /admin/users
     * Creates a new admin user with a temporary password.
     * Requires admin_user.manage permission.
     */
    @PostMapping
    @PreAuthorize("hasAuthority('admin_user.manage')")
    public ResponseEntity<ApiResponse<CreateAdminUserResponse>> createUser(
            @RequestHeader("X-Tenant-Id") UUID tenantId,
            @RequestHeader("X-User-Id") UUID callerId,
            @Valid @RequestBody CreateAdminUserRequest request) {

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok(adminUserService.createUser(tenantId, callerId, request)));
    }

    /**
     * GET /admin/users?page=0&size=20&status=ACTIVE
     * Lists admin users for the tenant with pagination.
     */
    @GetMapping
    @PreAuthorize("hasAuthority('admin_user.manage')")
    public ResponseEntity<ApiResponse<Page<UserResponse>>> listUsers(
            @RequestHeader("X-Tenant-Id") UUID tenantId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "ACTIVE") String status) {

        return ResponseEntity.ok(
                ApiResponse
                        .ok(adminUserService.listUsers(tenantId, status, PageRequest.of(page, Math.min(size, 100)))));
    }

    /**
     * PATCH /admin/users/{id}
     * Updates non-null fields of the admin user.
     */
    @PatchMapping("/{id}")
    @PreAuthorize("hasAuthority('admin_user.manage')")
    public ResponseEntity<ApiResponse<UserResponse>> updateUser(
            @RequestHeader("X-Tenant-Id") UUID tenantId,
            @PathVariable UUID id,
            @Valid @RequestBody UpdateAdminUserRequest request) {

        return ResponseEntity.ok(ApiResponse.ok(adminUserService.updateUser(tenantId, id, request)));
    }

    /**
     * POST /admin/users/{id}/deactivate
     * Soft-deactivates the user and revokes all refresh tokens.
     */
    @PostMapping("/{id}/deactivate")
    @PreAuthorize("hasAuthority('admin_user.manage')")
    public ResponseEntity<ApiResponse<Void>> deactivateUser(
            @RequestHeader("X-Tenant-Id") UUID tenantId,
            @RequestHeader("X-User-Id") UUID callerId,
            @PathVariable UUID id) {

        adminUserService.deactivateUser(tenantId, callerId, id);
        return ResponseEntity.ok(ApiResponse.ok(null));
    }

    /**
     * POST /admin/users/{id}/roles
     * Full replacement of the user's role assignments.
     */
    @PostMapping("/{id}/roles")
    @PreAuthorize("hasAuthority('admin_user.manage')")
    public ResponseEntity<ApiResponse<Void>> assignRoles(
            @RequestHeader("X-Tenant-Id") UUID tenantId,
            @RequestHeader("X-User-Id") UUID callerId,
            @PathVariable UUID id,
            @Valid @RequestBody AssignRolesRequest request) {

        adminUserService.assignRoles(tenantId, callerId, id, request);
        return ResponseEntity.ok(ApiResponse.ok(null));
    }

    /**
     * POST /admin/users/{id}/store-scopes
     * Full replacement of the user's store scope assignments.
     */
    @PostMapping("/{id}/store-scopes")
    @PreAuthorize("hasAuthority('admin_user.manage')")
    public ResponseEntity<ApiResponse<Void>> assignStoreScopes(
            @RequestHeader("X-Tenant-Id") UUID tenantId,
            @RequestHeader("X-User-Id") UUID callerId,
            @PathVariable UUID id,
            @Valid @RequestBody AssignStoreScopesRequest request) {

        adminUserService.assignStoreScopes(tenantId, callerId, id, request);
        return ResponseEntity.ok(ApiResponse.ok(null));
    }


}
