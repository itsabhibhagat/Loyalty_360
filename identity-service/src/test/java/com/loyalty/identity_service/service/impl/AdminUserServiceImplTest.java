package com.loyalty.identity_service.service.impl;

import com.loyalty.identity_service.dto.*;
import com.loyalty.identity_service.entity.AdminUser;
import com.loyalty.identity_service.entity.AdminUserStatus;
import com.loyalty.identity_service.entity.Role;
import com.loyalty.identity_service.exception.ConflictException;
import com.loyalty.identity_service.exception.ForbiddenException;
import com.loyalty.identity_service.exception.ResourceNotFoundException;
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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.hibernate.validator.internal.util.Contracts.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

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
    //TC: 1.1success
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

    //TC: 1.2 : Email already exists → ConflictException
    @Test
    void createUser_emailExists() {

        CreateAdminUserRequest request = new CreateAdminUserRequest();
        request.setEmail("test@mail.com");

        AdminUser existing = new AdminUser();
        existing.setStatus(AdminUserStatus.ACTIVE);

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(tenantId, request.getEmail()))
                .thenReturn(Optional.of(existing));

        assertThrows(ConflictException.class, () ->
                adminUserService.createUser(tenantId, callerId, request)
        );
    }

    // TC: 1.3:Role not found
    @Test
    void createUser_roleNotFound() {

        CreateAdminUserRequest request = new CreateAdminUserRequest();
        request.setEmail("test@mail.com");
        request.setRoleCodes(List.of("INVALID"));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(tenantId, request.getEmail()))
                .thenReturn(Optional.empty());

        when(roleRepository.findByCodeIn(request.getRoleCodes()))
                .thenReturn(List.of()); // mismatch

        assertThrows(ResourceNotFoundException.class, () ->
                adminUserService.createUser(tenantId, callerId, request)
        );
    }

    //TC:1.4: Caller has no roles
    @Test
    void createUser_noCallerRoles() {

        CreateAdminUserRequest request = new CreateAdminUserRequest();
        request.setEmail("test@mail.com");

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(tenantId, request.getEmail()))
                .thenReturn(Optional.empty());

        when(userRoleRepository.findRoleCodesByUserId(callerId))
                .thenReturn(List.of());

        assertThrows(ForbiddenException.class, () ->
                adminUserService.createUser(tenantId, callerId, request)
        );
    }

    // TC: 1.5 Role hierarchy violation
    @Test
    void createUser_invalidRoleHierarchy() {

        CreateAdminUserRequest request = new CreateAdminUserRequest();
        request.setEmail("test@mail.com");
        request.setRoleCodes(List.of("PLATFORM_OPERATOR"));

        Role role = new Role();
        role.setCode("PLATFORM_OPERATOR");
        role.setIsSystem(true);

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(tenantId, request.getEmail()))
                .thenReturn(Optional.empty());

        when(roleRepository.findByCodeIn(request.getRoleCodes()))
                .thenReturn(List.of(role));

        when(userRoleRepository.findRoleCodesByUserId(callerId))
                .thenReturn(List.of("STORE_ADMIN")); // lower role

        assertThrows(ForbiddenException.class, () ->
                adminUserService.createUser(tenantId, callerId, request)
        );
    }
//.....................................................................................

    //TC2: UPDATE USER...
    // TC: 2.1 update_user success
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
    //TC: 2.2: user not found
    @Test
    void updateUser_userNotFound() {

        UUID userId = UUID.randomUUID();

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () ->
                adminUserService.updateUser(tenantId, userId, new UpdateAdminUserRequest())
        );
    }

    //Tc: 2.3 Email already exists
    @Test
    void updateUser_emailExists() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);
        user.setEmail("old@mail.com");

        UpdateAdminUserRequest request = new UpdateAdminUserRequest();
        request.setEmail("new@mail.com");

        AdminUser existing = new AdminUser();
        existing.setStatus(AdminUserStatus.ACTIVE);

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        when(adminUserRepository.findByTenantIdAndEmailIgnoreCase(tenantId, "new@mail.com"))
                .thenReturn(Optional.of(existing));

        assertThrows(ConflictException.class, () ->
                adminUserService.updateUser(tenantId, userId, request)
        );
    }
    //TC: 2.4 Update Last Name:
    @Test
    void updateUser_lastNameOnly() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);

        UpdateAdminUserRequest request = new UpdateAdminUserRequest();
        request.setLastName("Updated");

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        when(userRoleRepository.findRoleCodesByUserId(userId)).thenReturn(List.of());
        when(userRoleRepository.findPermissionCodesByUserId(userId)).thenReturn(List.of());
        when(userStoreScopeRepository.findByUserId(userId)).thenReturn(List.of());

        UserResponse response =
                adminUserService.updateUser(tenantId, userId, request);

        assertEquals("Updated", response.getLastName());
    }

    //TC: 2.5 Same email (no check triggered)
    @Test
    void updateUser_sameEmail_noConflict() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);
        user.setEmail("same@mail.com");

        UpdateAdminUserRequest request = new UpdateAdminUserRequest();
        request.setEmail("same@mail.com");

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        when(userRoleRepository.findRoleCodesByUserId(userId)).thenReturn(List.of());
        when(userRoleRepository.findPermissionCodesByUserId(userId)).thenReturn(List.of());
        when(userStoreScopeRepository.findByUserId(userId)).thenReturn(List.of());

        UserResponse response =
                adminUserService.updateUser(tenantId, userId, request);

        assertEquals("same@mail.com", response.getEmail());
    }
//    .....................................................................................................

    //    TEST 3: deactivateUser
    // TC: 3.1 Successfully deactivating
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

    //3.2 User not found
    @Test
    void deactivateUser_userNotFound() {

        UUID userId = UUID.randomUUID();

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () ->
                adminUserService.deactivateUser(tenantId, callerId, userId)
        );
    }

    //3.3 Wrong tenant
    @Test
    void deactivateUser_wrongTenant() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(UUID.randomUUID());

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        assertThrows(ResourceNotFoundException.class, () ->
                adminUserService.deactivateUser(tenantId, callerId, userId)
        );
    }
    //3.4 Verify saved calls
    @Test
    void deactivateUser_verifySave() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        adminUserService.deactivateUser(tenantId, callerId, userId);

        verify(adminUserRepository).save(user);
    }

    //3.5 Verify audit call only once
    @Test
    void deactivateUser_verifyAuditOnce() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        adminUserService.deactivateUser(tenantId, callerId, userId);

        verify(auditService, times(1))
                .logUserDeactivated(tenantId, callerId, userId);
    }


//    -------------------------------------------------------------------------------

    //TCs: 4. ListUsers......
    //TC 4.1 Valid Status

    @Test
    void listUsers_validStatus() {

        Pageable pageable = PageRequest.of(0, 10);

        AdminUser user = new AdminUser();
        user.setId(UUID.randomUUID());
        user.setTenantId(tenantId);

        Page<AdminUser> page = new PageImpl<>(List.of(user));

        when(adminUserRepository.findByTenantIdAndStatus(
                tenantId, AdminUserStatus.ACTIVE, pageable))
                .thenReturn(page);

        when(userRoleRepository.findRoleCodesByUserId(any())).thenReturn(List.of());
        when(userRoleRepository.findPermissionCodesByUserId(any())).thenReturn(List.of());
        when(userStoreScopeRepository.findByUserId(any())).thenReturn(List.of());

        Page<UserResponse> result =
                adminUserService.listUsers(tenantId, "ACTIVE", pageable);

        assertEquals(1, result.getContent().size());
    }

    // 4.2 Invalid Status → fallback

    @Test
    void listUsers_invalidStatus() {

        Pageable pageable = PageRequest.of(0, 10);

        when(adminUserRepository.findByTenantId(tenantId, pageable))
                .thenReturn(new PageImpl<>(List.of()));

        Page<UserResponse> result =
                adminUserService.listUsers(tenantId, "WRONG", pageable);

        assertNotNull(result);
    }

    //    4.3 Null status
    @Test
    void listUsers_nullStatus() {

        Pageable pageable = PageRequest.of(0, 10);

        when(adminUserRepository.findByTenantId(tenantId, pageable))
                .thenReturn(new PageImpl<>(List.of()));

        Page<UserResponse> result =
                adminUserService.listUsers(tenantId, null, pageable);

        assertNotNull(result);
    }

    //4.4 Blank status (edge case)
    @Test
    void listUsers_blankStatus_shouldFallback() {

        Pageable pageable = PageRequest.of(0, 10);

        when(adminUserRepository.findByTenantId(tenantId, pageable))
                .thenReturn(new PageImpl<>(List.of()));

        Page<UserResponse> result =
                adminUserService.listUsers(tenantId, "   ", pageable);

        assertNotNull(result);

        verify(adminUserRepository).findByTenantId(tenantId, pageable);
    }

    //4.5.Verify correct repository method used for valid status
    @Test
    void listUsers_verifyCorrectRepositoryCall() {

        Pageable pageable = PageRequest.of(0, 10);

        when(adminUserRepository.findByTenantIdAndStatus(
                tenantId, AdminUserStatus.ACTIVE, pageable))
                .thenReturn(new PageImpl<>(List.of()));


        adminUserService.listUsers(tenantId, "ACTIVE", pageable);

        verify(adminUserRepository, times(1))
                .findByTenantIdAndStatus(tenantId, AdminUserStatus.ACTIVE, pageable);
    }

//    --------------------------------------------------------------------------------------------------


    //5. AssignRoles()
    //5.1 TC: Success
    @Test
    void assignRoles_success() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);

        AssignRolesRequest request = new AssignRolesRequest();
        request.setRoleCodes(List.of("STORE_ADMIN"));

        Role role = new Role();
        role.setCode("STORE_ADMIN");

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        when(roleRepository.findByCodeIn(request.getRoleCodes()))
                .thenReturn(List.of(role));

        adminUserService.assignRoles(tenantId, callerId, userId, request);

        verify(userRoleRepository).deleteByUserId(userId);
        verify(userRoleRepository).save(any());
        verify(auditService).logRolesAssigned(tenantId, callerId, userId);
    }

    //5.2 Empty role:
    @Test
    void assignRoles_emptyRoles() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);

        AssignRolesRequest request = new AssignRolesRequest();
        request.setRoleCodes(List.of());

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        adminUserService.assignRoles(tenantId, callerId, userId, request);

        verify(userRoleRepository).deleteByUserId(userId);
        verify(userRoleRepository, never()).save(any());
    }

    //    5.3 User Not Found
    @Test
    void assignRoles_userNotFound() {

        UUID userId = UUID.randomUUID();

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () ->
                adminUserService.assignRoles(tenantId, callerId, userId, new AssignRolesRequest())
        );
    }
    //    5.4 Multiple roles assigned
    @Test
    void assignRoles_multipleRoles() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);

        AssignRolesRequest request = new AssignRolesRequest();
        request.setRoleCodes(List.of("STORE_ADMIN", "CUSTOMER_SUPPORT"));

        Role role1 = new Role();
        role1.setCode("STORE_ADMIN");

        Role role2 = new Role();
        role2.setCode("CUSTOMER_SUPPORT");

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        when(roleRepository.findByCodeIn(request.getRoleCodes()))
                .thenReturn(List.of(role1, role2));

        adminUserService.assignRoles(tenantId, callerId, userId, request);

        verify(userRoleRepository, times(2)).save(any());
    }
    // 5.5 Verify delete always called before assigning
    @Test
    void assignRoles_verifyDeleteCalled() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);

        AssignRolesRequest request = new AssignRolesRequest();
        request.setRoleCodes(List.of("STORE_ADMIN"));

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        when(roleRepository.findByCodeIn(any()))
                .thenReturn(List.of(new Role()));

        adminUserService.assignRoles(tenantId, callerId, userId, request);

        verify(userRoleRepository).deleteByUserId(userId);
    }

//    --------------------------------------------------------------------------------------------------------------------

    //    6:TC: AssignStoreScopes()
    // 6.1: Success:
    @Test
    void assignStoreScopes_success() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);

        AssignStoreScopesRequest request = new AssignStoreScopesRequest();

        AssignStoreScopesRequest.StoreScopeEntry scope =
                new AssignStoreScopesRequest.StoreScopeEntry();
        scope.setBrandId(UUID.randomUUID());
        scope.setStoreId(UUID.randomUUID());

        request.setScopes(List.of(scope));

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        adminUserService.assignStoreScopes(tenantId, callerId, userId, request);

        verify(userStoreScopeRepository).deleteByUserId(userId);
        verify(userStoreScopeRepository).save(any());
        verify(auditService).logStoreScopesAssigned(tenantId, callerId, userId);
    }

    //6.2: Empty scopes:
    @Test
    void assignStoreScopes_empty() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);

        AssignStoreScopesRequest request = new AssignStoreScopesRequest();
        request.setScopes(List.of());

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        adminUserService.assignStoreScopes(tenantId, callerId, userId, request);

        verify(userStoreScopeRepository).deleteByUserId(userId);
        verify(userStoreScopeRepository, never()).save(any());
    }

    //6.3 User not found:
    @Test
    void assignStoreScopes_userNotFound() {

        UUID userId = UUID.randomUUID();

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () ->
                adminUserService.assignStoreScopes(tenantId, callerId, userId, new AssignStoreScopesRequest())
        );
    }

    //6.4 Multiple scopes assigned
    @Test
    void assignStoreScopes_multipleScopes() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);

        AssignStoreScopesRequest request = new AssignStoreScopesRequest();

        AssignStoreScopesRequest.StoreScopeEntry scope1 =
                new AssignStoreScopesRequest.StoreScopeEntry();
        scope1.setBrandId(UUID.randomUUID());
        scope1.setStoreId(UUID.randomUUID());

        AssignStoreScopesRequest.StoreScopeEntry scope2 =
                new AssignStoreScopesRequest.StoreScopeEntry();
        scope2.setBrandId(UUID.randomUUID());
        scope2.setStoreId(UUID.randomUUID());

        request.setScopes(List.of(scope1, scope2));

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        adminUserService.assignStoreScopes(tenantId, callerId, userId, request);

        verify(userStoreScopeRepository, times(2)).save(any());
    }

    //6.5 Verify audit always called
    @Test
    void assignStoreScopes_verifyAuditCalled() {

        UUID userId = UUID.randomUUID();

        AdminUser user = new AdminUser();
        user.setId(userId);
        user.setTenantId(tenantId);

        AssignStoreScopesRequest request = new AssignStoreScopesRequest();
        request.setScopes(List.of());

        when(adminUserRepository.findById(userId))
                .thenReturn(Optional.of(user));

        adminUserService.assignStoreScopes(tenantId, callerId, userId, request);

        verify(auditService, times(1))
                .logStoreScopesAssigned(tenantId, callerId, userId);
    }
}