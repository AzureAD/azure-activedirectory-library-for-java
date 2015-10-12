/*******************************************************************************
 * Copyright © Microsoft Open Technologies, Inc.
 * 
 * All Rights Reserved
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 * 
 * See the Apache License, Version 2.0 for the specific language
 * governing permissions and limitations under the License.
 ******************************************************************************/
package com.microsoft.aad.adal4j;

import java.net.Proxy;
import java.net.URL;
import java.util.Arrays;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents Authentication Authority responsible for issuing access tokens.
 */
class AuthenticationAuthority {
    private final Logger log = LoggerFactory
            .getLogger(AuthenticationAuthority.class);

    private final static String[] TRUSTED_HOST_LIST = { "login.windows.net",
            "login.chinacloudapi.cn", "login.cloudgovapi.us", "login.microsoftonline.com" };
    private final static String TENANTLESS_TENANT_NAME = "common";
    private final static String AUTHORIZE_ENDPOINT_TEMPLATE = "https://{host}/{tenant}/oauth2/authorize";
    private final static String DISCOVERY_ENDPOINT = "common/discovery/instance";
    private final static String TOKEN_ENDPOINT = "/oauth2/token";
    private final static String USER_REALM_ENDPOINT = "common/userrealm";

    private String host;
    private String issuer;
    private final String instanceDiscoveryEndpointFormat = "https://%s/"
            + DISCOVERY_ENDPOINT;
    private final String userRealmEndpointFormat = "https://%s/"
            + USER_REALM_ENDPOINT + "/%s?api-version=1.0";
    private final String tokenEndpointFormat = "https://%s/{tenant}"
            + TOKEN_ENDPOINT;
    private String authority = "https://%s/%s/";
    private String instanceDiscoveryEndpoint;
    private String tokenEndpoint;

    private final AuthorityType authorityType;
    private boolean isTenantless;
    private String tokenUri;
    private String selfSignedJwtAudience;
    private boolean instanceDiscoveryCompleted;

    private final URL authorityUrl;
    private final boolean validateAuthority;

    private Proxy proxy;

    AuthenticationAuthority(final URL authorityUrl,
            final boolean validateAuthority) {

        this.authorityUrl = authorityUrl;
        this.authorityType = detectAuthorityType();
        this.validateAuthority = validateAuthority;
        validateAuthorityUrl();
        setupAuthorityProperties();
    }

    public Proxy getProxy() {
        return proxy;
    }

    public void setProxy(Proxy proxy) {
        this.proxy = proxy;
    }

    String getHost() {
        return host;
    }

    String getIssuer() {
        return issuer;
    }

    String getAuthority() {
        return authority;
    }

    String getTokenEndpoint() {
        return tokenEndpoint;
    }
    
    String getUserRealmEndpoint(String username) {
        return String.format(userRealmEndpointFormat, host, username);
    }
    
    AuthorityType getAuthorityType() {
        return authorityType;
    }

    boolean isTenantless() {
        return isTenantless;
    }

    String getTokenUri() {
        return tokenUri;
    }

    String getSelfSignedJwtAudience() {
        return selfSignedJwtAudience;
    }

    void setSelfSignedJwtAudience(final String selfSignedJwtAudience) {
        this.selfSignedJwtAudience = selfSignedJwtAudience;
    }

    void doInstanceDiscovery(final Map<String, String> headers)
            throws Exception {

        // instance discovery should be executed only once per context instance.
        if (!instanceDiscoveryCompleted) {
            // matching against static list failed
            if (!doStaticInstanceDiscovery()) {
                // if authority must be validated and dynamic discovery request
                // as a fall back is success
                if (validateAuthority && !doDynamicInstanceDiscovery(headers)) {
                    throw new AuthenticationException(
                            AuthenticationErrorMessage.AUTHORITY_NOT_IN_VALID_LIST);
                }
            }
            log.info(LogHelper.createMessage(
                    "Instance discovery was successful",
                    headers.get(ClientDataHttpHeaders.CORRELATION_ID_HEADER_NAME)));
            instanceDiscoveryCompleted = true;
        }
    }

    boolean doDynamicInstanceDiscovery(final Map<String, String> headers)
            throws Exception {
        final String json = HttpHelper.executeHttpGet(log, instanceDiscoveryEndpoint, headers, proxy);
        final InstanceDiscoveryResponse discoveryResponse = JsonHelper
                .convertJsonToObject(json, InstanceDiscoveryResponse.class);
        return !StringHelper.isBlank(discoveryResponse
                .getTenantDiscoveryEndpoint());
    }

    boolean doStaticInstanceDiscovery() {
        if (validateAuthority) {
            return Arrays.asList(TRUSTED_HOST_LIST).contains(this.host);
        }
        return true;
    }

    void setupAuthorityProperties() {

        final String host = this.authorityUrl.getAuthority().toLowerCase();
        final String path = this.authorityUrl.getPath().substring(1)
                .toLowerCase();
        final String tenant = path.substring(0, path.indexOf("/"))
                .toLowerCase();

        this.host = host;
        this.authority = String.format(this.authority, host, tenant);
        this.instanceDiscoveryEndpoint = String.format(
                this.instanceDiscoveryEndpointFormat, host);
        this.tokenEndpoint = String.format(this.tokenEndpointFormat, host);
        this.tokenEndpoint = this.tokenEndpoint.replace("{tenant}", tenant);
        this.tokenUri = this.tokenEndpoint;
        this.issuer = this.tokenUri;

        this.isTenantless = TENANTLESS_TENANT_NAME.equalsIgnoreCase(tenant);
        this.setSelfSignedJwtAudience(this.getIssuer());
        this.createInstanceDiscoveryEndpoint(tenant);
    }

    AuthorityType detectAuthorityType() {
        if (authorityUrl == null) {
            throw new NullPointerException("authority");
        }

        final String path = authorityUrl.getPath().substring(1);
        if (StringHelper.isBlank(path)) {
            throw new IllegalArgumentException(
                    AuthenticationErrorMessage.AUTHORITY_URI_INVALID_PATH);
        }

        final String firstPath = path.substring(0, path.indexOf("/"));
        final AuthorityType authorityType = IsAdfsAuthority(firstPath) ? AuthorityType.ADFS
                : AuthorityType.AAD;

        return authorityType;
    }

    void validateAuthorityUrl() {

        if (authorityType != AuthorityType.AAD && validateAuthority) {
            throw new IllegalArgumentException(
                    AuthenticationErrorMessage.UNSUPPORTED_AUTHORITY_VALIDATION);
        }

        if (!this.authorityUrl.getProtocol().equalsIgnoreCase("https")) {
            throw new IllegalArgumentException(
                    AuthenticationErrorMessage.AUTHORITY_URI_INSECURE);
        }

        if (this.authorityUrl.toString().contains("#")) {
            throw new IllegalArgumentException(
                    "authority is invalid format (contains fragment)");
        }

        if (!StringHelper.isBlank(this.authorityUrl.getQuery())) {
            throw new IllegalArgumentException(
                    "authority cannot contain query parameters");
        }
    }

    void createInstanceDiscoveryEndpoint(final String tenant) {
        this.instanceDiscoveryEndpoint += "?api-version=1.0&authorization_endpoint="
                + AUTHORIZE_ENDPOINT_TEMPLATE;
        this.instanceDiscoveryEndpoint = this.instanceDiscoveryEndpoint
                .replace("{host}", host);
        this.instanceDiscoveryEndpoint = this.instanceDiscoveryEndpoint
                .replace("{tenant}", tenant);
    }

    static boolean IsAdfsAuthority(final String firstPath) {
        return firstPath.compareToIgnoreCase("adfs") == 0;
    }
}
