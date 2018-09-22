// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package com.microsoft.aad.adal4j;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.SAML2BearerGrant;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import org.apache.commons.codec.binary.Base64;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class AcquireTokenCallable extends AdalCallable<AuthenticationResult> {
    private AdalAuthorizationGrant authGrant;
    private ClientAuthentication clientAuth;

    AcquireTokenCallable(AuthenticationContext context,
                         AdalAuthorizationGrant authGrant, ClientAuthentication clientAuth,
                         AuthenticationCallback<AuthenticationResult> callback) {
        super(context, callback);
        this.authGrant = authGrant;
        this.clientAuth = clientAuth;

        String correlationId = context.correlationId;
        if (StringHelper.isBlank(correlationId) &&
                authGrant instanceof AdalDeviceCodeAuthorizationGrant) {
            correlationId = ((AdalDeviceCodeAuthorizationGrant) authGrant).getCorrelationId();
        }

        this.headers = new ClientDataHttpHeaders(correlationId);
    }

    AuthenticationResult execute() throws Exception {
        if (authGrant instanceof AdalOAuthAuthorizationGrant) {
            authGrant = processPasswordGrant((AdalOAuthAuthorizationGrant) authGrant);
        }

        if (this.authGrant instanceof AdalIntegratedAuthorizationGrant) {
            AdalIntegratedAuthorizationGrant integratedAuthGrant = (AdalIntegratedAuthorizationGrant) authGrant;
            authGrant = new AdalOAuthAuthorizationGrant(
                    getAuthorizationGrantIntegrated(integratedAuthGrant.getUserName()),
                    integratedAuthGrant.getResource());
        }

        return context.acquireTokenCommon(this.authGrant, this.clientAuth, this.headers);
    }

    @Override
    void logResult(AuthenticationResult result, ClientDataHttpHeaders headers)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {

        if (!StringHelper.isBlank(result.getAccessToken())) {

            String accessTokenHash = this.computeSha256Hash(result
                    .getAccessToken());
            if (!StringHelper.isBlank(result.getRefreshToken())) {
                String refreshTokenHash = this.computeSha256Hash(result
                        .getRefreshToken());
                if(context.isLogPii()){
                    context.log.debug(LogHelper.createMessage(String
                                    .format("Access Token with hash '%s' and Refresh Token with hash '%s' returned",
                                            accessTokenHash, refreshTokenHash),
                            headers.getHeaderCorrelationIdValue()));
                }
                else{
                    context.log.debug(LogHelper.createMessage("Access Token and Refresh Token were returned",
                            headers.getHeaderCorrelationIdValue()));
                }
            }
            else {
                if(context.isLogPii()){
                    context.log.debug(LogHelper.createMessage(String
                                    .format("Access Token with hash '%s' returned",
                                            accessTokenHash),
                            headers.getHeaderCorrelationIdValue()));
                }
                else{
                    context.log.debug(LogHelper.createMessage("Access Token was returned",
                            headers.getHeaderCorrelationIdValue()));
                }
            }
        }
    }

    private String computeSha256Hash(String input)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(input.getBytes("UTF-8"));
        byte[] hash = digest.digest();
        return Base64.encodeBase64URLSafeString(hash);
    }

    /**
     * @param authGrant
     */
    private AdalOAuthAuthorizationGrant processPasswordGrant(
            AdalOAuthAuthorizationGrant authGrant) throws Exception {

        if (!(authGrant.getAuthorizationGrant() instanceof ResourceOwnerPasswordCredentialsGrant)) {
            return authGrant;
        }

        ResourceOwnerPasswordCredentialsGrant grant = (ResourceOwnerPasswordCredentialsGrant) authGrant
                .getAuthorizationGrant();

        UserDiscoveryResponse userDiscoveryResponse = UserDiscoveryRequest.execute(
                context.authenticationAuthority.getUserRealmEndpoint(grant.getUsername()),
                this.headers.getReadonlyHeaderMap(),
                context.proxy, 
                context.sslSocketFactory);
        if (userDiscoveryResponse.isAccountFederated()) {
            WSTrustResponse response = WSTrustRequest.execute(
                    userDiscoveryResponse.getFederationMetadataUrl(),
                    grant.getUsername(), grant.getPassword().getValue(), userDiscoveryResponse.getCloudAudienceUrn(),
                    context.proxy, context.sslSocketFactory, context.isLogPii());

            AuthorizationGrant updatedGrant = null;
            if (response.isTokenSaml2()) {
                updatedGrant = new SAML2BearerGrant(new Base64URL(
                        Base64.encodeBase64String(response.getToken().getBytes(
                                "UTF-8"))));
            }
            else {
                updatedGrant = new SAML11BearerGrant(new Base64URL(
                        Base64.encodeBase64String(response.getToken()
                                .getBytes())));
            }

            authGrant = new AdalOAuthAuthorizationGrant(updatedGrant,
                    authGrant.getCustomParameters());
        }

        return authGrant;
    }

    AuthorizationGrant getAuthorizationGrantIntegrated(String userName) throws Exception {
        AuthorizationGrant updatedGrant;

        String userRealmEndpoint = context.authenticationAuthority.
                getUserRealmEndpoint(URLEncoder.encode(userName, "UTF-8"));

        // Get the realm information
        UserDiscoveryResponse userRealmResponse = UserDiscoveryRequest.execute(
                userRealmEndpoint, 
                this.headers.getReadonlyHeaderMap(), 
                context.proxy, 
                context.sslSocketFactory);

        if (userRealmResponse.isAccountFederated() &&
                "WSTrust".equalsIgnoreCase(userRealmResponse.getFederationProtocol())) {
            String mexURL = userRealmResponse.getFederationMetadataUrl();
            String cloudAudienceUrn = userRealmResponse.getCloudAudienceUrn();

            // Discover the policy for authentication using the Metadata Exchange Url.
            // Get the WSTrust Token (Web Service Trust Token)
            WSTrustResponse wsTrustResponse = WSTrustRequest.execute
                    (mexURL, cloudAudienceUrn, context.proxy, context.sslSocketFactory, context.isLogPii());

            if (wsTrustResponse.isTokenSaml2()) {
                updatedGrant = new SAML2BearerGrant(
                        new Base64URL(Base64.encodeBase64String(wsTrustResponse.getToken().getBytes("UTF-8"))));
            }
            else {
                updatedGrant = new SAML11BearerGrant(
                        new Base64URL(Base64.encodeBase64String(wsTrustResponse.getToken().getBytes())));
            }
        }
        else if (userRealmResponse.isAccountManaged()) {
            throw new AuthenticationException("Password is required for managed user");
        }
        else{
            throw new AuthenticationException("Unknown User Type");
        }

        return updatedGrant;
    }
}
