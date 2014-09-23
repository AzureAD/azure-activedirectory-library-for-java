package com.microsoft.aad.adal4j;

import com.google.gson.annotations.SerializedName;

class UserDiscoveryResponse {
    
    @SerializedName("tenant_discovery_endpoint")
    private String tenantDiscoveryEndpoint;

    String getTenantDiscoveryEndpoint() {
        return tenantDiscoveryEndpoint;
    }
}
