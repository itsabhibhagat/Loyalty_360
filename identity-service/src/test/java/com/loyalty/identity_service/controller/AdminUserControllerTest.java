package com.loyalty.identity_service.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.loyalty.identity_service.dto.*;
import com.loyalty.identity_service.service.AdminUserService;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AdminUserController.class)
@AutoConfigureMockMvc(addFilters = false)
class AdminUserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AdminUserService adminUserService;

    @Autowired
    private ObjectMapper objectMapper;

//    Test: Create User (POST)
    @Test
    @WithMockUser(authorities = "admin_user.manage")

    void createUser_shouldReturnCreated() throws Exception {
        UUID tenantId = UUID.randomUUID();
        UUID callerId = UUID.randomUUID();

        CreateAdminUserRequest request = new CreateAdminUserRequest();
        request.setEmail("test@test.com");
        request.setFirstName("John");
        request.setLastName("Doe");
        CreateAdminUserResponse response = new CreateAdminUserResponse();

        Mockito.when(adminUserService.createUser(
                Mockito.eq(tenantId),
                Mockito.eq(callerId),
                Mockito.any(CreateAdminUserRequest.class)
        )).thenReturn(response);

        mockMvc.perform(post("/admin/users")
                        .header("X-Tenant-Id", tenantId.toString())
                        .header("X-User-Id", callerId.toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true));
    }
    // 2. Test: List Users (GET)
    @Test
    @WithMockUser(authorities = "admin_user.manage")
    void listUsers_shouldReturnOk() throws Exception {
        UUID tenantId = UUID.randomUUID();

        Page<UserResponse> page = new PageImpl<>(List.of(new UserResponse()));

        Mockito.when(adminUserService.listUsers(
                Mockito.eq(tenantId),
                Mockito.anyString(),
                Mockito.any(PageRequest.class)
        )).thenReturn(page);

        mockMvc.perform(get("/admin/users")
                        .header("X-Tenant-Id", tenantId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    // 3. UpdateUser
    @Test
    @WithMockUser(authorities = "admin_user.manage")
    void updateUser_shouldReturnOk() throws Exception {
        UUID tenantId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();

        UpdateAdminUserRequest request = new UpdateAdminUserRequest();
        UserResponse response = new UserResponse();

        Mockito.when(adminUserService.updateUser(
                Mockito.eq(tenantId),
                Mockito.eq(userId),
                Mockito.any(UpdateAdminUserRequest.class)
        )).thenReturn(response);

        mockMvc.perform(patch("/admin/users/{id}", userId)
                        .header("X-Tenant-Id", tenantId.toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }


    // 4. Deactivate User
    @Test
    @WithMockUser(authorities = "admin_user.manage")
    void deactivateUser_shouldReturnOk() throws Exception {
        UUID tenantId = UUID.randomUUID();
        UUID callerId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();

        mockMvc.perform(post("/admin/users/{id}/deactivate", userId)
                        .header("X-Tenant-Id", tenantId.toString())
                        .header("X-User-Id", callerId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        Mockito.verify(adminUserService).deactivateUser(tenantId, callerId, userId);
    }

    // 5. assignRoles test
    @Test
    @WithMockUser(authorities = "admin_user.manage")
    void assignRoles_shouldReturnOk() throws Exception {
        UUID tenantId = UUID.randomUUID();
        UUID callerId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();

        AssignRolesRequest request = new AssignRolesRequest();

        mockMvc.perform(post("/admin/users/{id}/roles", userId)
                        .header("X-Tenant-Id", tenantId.toString())
                        .header("X-User-Id", callerId.toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        Mockito.verify(adminUserService)
                .assignRoles(Mockito.eq(tenantId), Mockito.eq(callerId), Mockito.eq(userId), Mockito.any());
    }

    // 6. assignStoreScopes test
    @Test
    @WithMockUser(authorities = "admin_user.manage")
    void assignStoreScopes_shouldReturnOk() throws Exception {
        UUID tenantId = UUID.randomUUID();
        UUID callerId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();

        AssignStoreScopesRequest request = new AssignStoreScopesRequest();

        mockMvc.perform(post("/admin/users/{id}/store-scopes", userId)
                        .header("X-Tenant-Id", tenantId.toString())
                        .header("X-User-Id", callerId.toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        Mockito.verify(adminUserService)
                .assignStoreScopes(Mockito.eq(tenantId), Mockito.eq(callerId), Mockito.eq(userId), Mockito.any());
    }

    // 7. Missing header test
    @Test
    @WithMockUser(authorities = "admin_user.manage")
    void createUser_missingTenantHeader_shouldFail() throws Exception {
        mockMvc.perform(post("/admin/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    // 8. Validation failure test

    @Test
    @WithMockUser(authorities = "admin_user.manage")
    void createUser_invalidRequest_shouldReturnBadRequest() throws Exception {
        UUID tenantId = UUID.randomUUID();
        UUID callerId = UUID.randomUUID();

        CreateAdminUserRequest request = new CreateAdminUserRequest(); // empty -> invalid

        mockMvc.perform(post("/admin/users")
                        .header("X-Tenant-Id", tenantId.toString())
                        .header("X-User-Id", callerId.toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(authorities = "admin_user.manage")
    void listUsers_sizeGreaterThan100_shouldCapTo100() throws Exception {
        UUID tenantId = UUID.randomUUID();

        mockMvc.perform(get("/admin/users")
                        .header("X-Tenant-Id", tenantId.toString())
                        .param("size", "200"))
                .andExpect(status().isOk());

        Mockito.verify(adminUserService).listUsers(
                Mockito.eq(tenantId),
                Mockito.anyString(),
                Mockito.argThat(pageRequest -> pageRequest.getPageSize() == 100)
        );
    }

    //Add missing header test for deactivate
    @Test
    @WithMockUser(authorities = "admin_user.manage")
    void deactivateUser_missingCallerHeader_shouldFail() throws Exception {
        UUID tenantId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();

        mockMvc.perform(post("/admin/users/{id}/deactivate", userId)
                        .header("X-Tenant-Id", tenantId.toString()))
                .andExpect(status().isBadRequest());
    }

    // edge case: Add invalid UUID test
    @Test
    @WithMockUser(authorities = "admin_user.manage")
    void updateUser_invalidUUID_shouldFail() throws Exception {

        mockMvc.perform(patch("/admin/users/{id}", "invalid-uuid")
                        .header("X-Tenant-Id", UUID.randomUUID().toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }


}
