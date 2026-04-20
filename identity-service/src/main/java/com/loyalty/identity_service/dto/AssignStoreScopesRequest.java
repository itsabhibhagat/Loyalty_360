package com.loyalty.identity_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;
import java.util.UUID;

@Data
public class AssignStoreScopesRequest {
    private List<StoreScopeEntry> scopes;

    @Data
    public static class StoreScopeEntry {
        @JsonProperty("brand_id")
        private UUID brandId;

        @JsonProperty("store_id")
        private UUID storeId;
    }
}
