package com.loyalty.identity_service.service.impl;

import com.loyalty.identity_service.dto.CreateAdminUserRequest;
import com.loyalty.identity_service.dto.CreateAdminUserResponse;
import com.loyalty.identity_service.dto.UpdateAdminUserRequest;
import com.loyalty.identity_service.dto.UserResponse;
import com.loyalty.identity_service.entity.AdminUser;
import com.loyalty.identity_service.entity.AdminUserStatus;
import com.loyalty.identity_service.entity.Role;
import com.loyalty.identity_service.repository.AdminUserRepository;
import com.loyalty.identity_service.repository.RoleRepository;
import com.loyalty.identity_service.repository.UserRoleRepository;
import com.loyalty.identity_service.repository.UserStoreScopeRepository;
import com.loyalty.identity_service.service.AuditService;
import com.loyalty.identity_service.service.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdminUserServiceImplTest {

    @Mock
    private AdminUserRepository adminUserRepository;

    @Mock
    private UserRoleRepository userRoleRepository;

    @Mock
    private UserStoreScopeRepository userStoreScopeRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private AuditService auditService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private AdminUserServiceImpl adminUserService;

    private UUID tenantId;
    private UUID callerId;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        callerId = UUID.randomUUID();
    }

    //TC1: Create user
    @Test
    void createUser_success() {

        CreateAdminUserRequest request = new CreateAdminUserRequest();
        request.setEmail("test@mail.com");
        request.setFirstName("Dev");
        request.setLastName("Goyal");
        request.setRoleCodes(List.of("STORE_ADMIN"));

        Role role = new Role();
        role.setCode("STORE_ADMIN");
        role.setIsSystem(true);

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(tenantId, request.getEmail()))
                .thenReturn(Optional.empty());

        when(roleRepository.findByCodeIn(request.getRoleCodes()))
                .thenReturn(List.of(role));

        when(userRoleRepository.findRoleCodesByUserId(callerId))
                .thenReturn(List.of("TENANT_OWNER"));

        when(passwordEncoder.encode(any()))
                .thenReturn("hashed");

        when(adminUserRepository.save(any()))
                .thenAnswer(invocation -> {
                    AdminUser user = invocation.getArgument(0);
                    user.setId(UUID.randomUUID());
                    return user;
                });

        CreateAdminUserResponse response =
                adminUserService.createUser(tenantId, callerId, request);

        assertNotNull(response);
        assertEquals("test@mail.com", response.getEmail());

        verify(adminUserRepository).save(any());
        verify(auditService).logUserCreated(eq(tenantId), eq(callerId), any());
    }
    //TC2: UPDATE USER...
    @Test
    void updateUser_success() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);
        user.setEmail("old@mail.com");

        UpdateAdminUserRequest request = new UpdateAdminUserRequest();
        request.setFirstName("NewName");

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        when(userRoleRepository.findRoleCodesByUserId(userId)).thenReturn(List.of());
        when(userRoleRepository.findPermissionCodesByUserId(userId)).thenReturn(List.of());
        when(userStoreScopeRepository.findByUserId(userId)).thenReturn(List.of());

        UserResponse response =
                adminUserService.updateUser(tenantId, userId, request);

        assertEquals("NewName", response.getFirstName());
        verify(adminUserRepository).save(user);
    }

//    TEST 3: deactivateUser
    @Test
    void deactivateUser_success() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        adminUserService.deactivateUser(tenantId, callerId, userId);

        assertEquals(AdminUserStatus.DISABLED, user.getStatus());

        verify(refreshTokenService).revokeAllUserTokens(userId);
        verify(auditService).logUserDeactivated(tenantId, callerId, userId);
    }
}