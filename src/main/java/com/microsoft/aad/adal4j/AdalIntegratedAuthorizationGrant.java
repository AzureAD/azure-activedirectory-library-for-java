package com.microsoft.aad.adal4j;

import java.util.Map;

public class AdalIntegratedAuthorizationGrant implements AdalAuthorizationGrant {

    private final String resource;

    private final String userName;

    AdalIntegratedAuthorizationGrant(String userName, String resource){
        this.userName = userName;
        this.resource = resource;
    }

    @Override
    public Map<String, String> toParameters() {
        return null;
    }

    public String getResource() {
        return resource;
    }

    public String getUserName() {
        return userName;
    }
}
