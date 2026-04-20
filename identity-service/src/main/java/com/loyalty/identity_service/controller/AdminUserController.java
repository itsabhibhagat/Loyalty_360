package com.loyalty.identity_service.controller;

import com.loyalty.identity_service.dto.ApiResponse;
import com.loyalty.identity_service.dto.UserResponse;
import com.loyalty.identity_service.service.AdminUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
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
}
