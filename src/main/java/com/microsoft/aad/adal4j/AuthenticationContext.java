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

import javax.net.ssl.SSLSocketFactory;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.JWTBearerGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.SAML2BearerGrant;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The main class representing the authority issuing tokens for resources. It
 * provides several ways to request access token, namely via Authorization Code,
 * Confidential Client and Client Certificate.
 */
public class AuthenticationContext {

    private final Logger log = LoggerFactory
            .getLogger(AuthenticationContext.class);

    private final AuthenticationAuthority authenticationAuthority;
    private String correlationId;
    private String authority;
    private final ExecutorService service;
    private final boolean validateAuthority;
    private Proxy proxy;
    private SSLSocketFactory sslSocketFactory;

    /**
     * Constructor to create the context with the address of the authority.
     *
     * @param authority
     *            URL of the authenticating authority
     * @param validateAuthority
     *            flag to enable/disable authority validation.
     * @param service
     *            ExecutorService to be used to execute the requests. Developer
     *            is responsible for maintaining the lifetime of the
     *            ExecutorService.
     * @throws MalformedURLException
     *             thrown if URL is invalid
     */
    public AuthenticationContext(final String authority,
            final boolean validateAuthority, final ExecutorService service)
            throws MalformedURLException {

        if (StringHelper.isBlank(authority)) {
            throw new IllegalArgumentException("authority is null or empty");
        }

        if (service == null) {
            throw new IllegalArgumentException("service is null");
        }
        this.service = service;
        this.validateAuthority = validateAuthority;
        this.authority = this.canonicalizeUri(authority);

        authenticationAuthority = new AuthenticationAuthority(new URL(
                this.getAuthority()), this.shouldValidateAuthority());
    }

    /**
     * Returns Proxy configuration
     * 
     * @return Proxy Object
     */
    public Proxy getProxy() {
        return proxy;
    }

    /**
     * Sets Proxy configuration to be used by the context for all network
     * communication. Default is null and system defined properties if any,
     * would be used.
     * 
     * @param proxy
     *            Proxy configuration object
     */
    public void setProxy(Proxy proxy) {
        this.proxy = proxy;
    }

    /**
     * Returns SSLSocketFactory configuration object.
     * 
     * @return SSLSocketFactory object
     */
    public SSLSocketFactory getSslSocketFactory() {
        return sslSocketFactory;
    }

    /**
     * Sets SSLSocketFactory object to be used by the context.
     * 
     * @param sslSocketFactory The SSL factory object to set
     */
    public void setSslSocketFactory(SSLSocketFactory sslSocketFactory) {
        this.sslSocketFactory = sslSocketFactory;
    }

    private String canonicalizeUri(String authority) {
        if (!authority.endsWith("/")) {
            authority += "/";
        }
        return authority;
    }

    private Future<AuthenticationResult> acquireToken(
            final AdalAuthorizatonGrant authGrant,
            final ClientAuthentication clientAuth,
            final AuthenticationCallback callback) {

        return service.submit(new Callable<AuthenticationResult>() {

            private AdalAuthorizatonGrant authGrant;
            private ClientAuthentication clientAuth;
            private ClientDataHttpHeaders headers;

            @Override
            public AuthenticationResult call() throws Exception {
                AuthenticationResult result = null;
                try {
                    this.authGrant = processPasswordGrant(this.authGrant);
                    result = acquireTokenCommon(this.authGrant,
                            this.clientAuth, this.headers);
                    logResult(result, headers);
                    if (callback != null) {
                        callback.onSuccess(result);
                    }
                }
                catch (final Exception ex) {
                    log.error(LogHelper.createMessage(
                            "Request to acquire token failed.",
                            this.headers.getHeaderCorrelationIdValue()), ex);
                    if (callback != null) {
                        callback.onFailure(ex);
                    }
                    else {
                        throw ex;
                    }
                }
                return result;
            }

            private Callable<AuthenticationResult> init(
                    final AdalAuthorizatonGrant authGrant,
                    final ClientAuthentication clientAuth,
                    final ClientDataHttpHeaders headers) {
                this.authGrant = authGrant;
                this.clientAuth = clientAuth;
                this.headers = headers;
                return this;
            }
        }.init(authGrant, clientAuth,
                new ClientDataHttpHeaders(this.getCorrelationId())));
    }

    /**
     * Acquires a security token from the authority using a Refresh Token
     * previously received.
     *
     * @param clientId
     *            Name or ID of the client requesting the token.
     * @param resource
     *            Identifier of the target resource that is the recipient of the
     *            requested token. If null, token is requested for the same
     *            resource refresh token was originally issued for. If passed,
     *            resource should match the original resource used to acquire
     *            refresh token unless token service supports refresh token for
     *            multiple resources.
     * @param username
     *            Username of the managed or federated user.
     * @param password
     *            Password of the managed or federated user.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     */
    public Future<AuthenticationResult> acquireToken(final String resource,
            final String clientId, final String username,
            final String password, final AuthenticationCallback callback) {
        if (StringHelper.isBlank(resource)) {
            throw new IllegalArgumentException("resource is null or empty");
        }

        if (StringHelper.isBlank(clientId)) {
            throw new IllegalArgumentException("clientId is null or empty");
        }

        if (StringHelper.isBlank(username)) {
            throw new IllegalArgumentException("username is null or empty");
        }

        if (StringHelper.isBlank(password)) {
            throw new IllegalArgumentException("password is null or empty");
        }

        return this.acquireToken(new AdalAuthorizatonGrant(
                new ResourceOwnerPasswordCredentialsGrant(username, new Secret(
                        password)), resource), new ClientAuthenticationPost(
                ClientAuthenticationMethod.NONE, new ClientID(clientId)),
                callback);
    }

    /**
     * Acquires security token from the authority.
     *
     * @param resource
     *            Identifier of the target resource that is the recipient of the
     *            requested token.
     * @param clientAssertion
     *            The client assertion to use for client authentication.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token and the Access Token's expiration time. Refresh Token
     *         property will be null for this overload.
     */
    public Future<AuthenticationResult> acquireToken(final String resource,
            final ClientAssertion clientAssertion,
            final AuthenticationCallback callback) {

        this.validateInput(resource, clientAssertion, true);
        final ClientAuthentication clientAuth = createClientAuthFromClientAssertion(clientAssertion);
        final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(
                new ClientCredentialsGrant(), resource);
        return this.acquireToken(authGrant, clientAuth, callback);
    }
    
    
    
    
    
    
    
	public Future<AuthenticationResult> acquireTokenIntegrated(AuthenticationContext context, final String resource, final String clientId,
			final AuthenticationCallback callback) {
		try {
			// User Realm Information Endpoint
			String userRealmEndpoint = context.authenticationAuthority.getUserRealmEndpoint(URLEncoder.encode("testodbc@microsoft.com", "UTF-8"));
			
			// Get the realm information
			UserDiscoveryResponse userRealmResponse = UserDiscoveryRequest.execute(userRealmEndpoint, this.proxy,
					this.sslSocketFactory);

			if (userRealmResponse.isAccountFederated()
					&& "WSTrust".equalsIgnoreCase(userRealmResponse.getFederationProtocol())) {
				
				System.out.println("isAccountFederated!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
				
				String mexURL = userRealmResponse.getFederationMetadataUrl();
				String cloudAudienceUrn = userRealmResponse.getCloudAudienceUrn();

				System.out.println("mexURL: " + mexURL);
				System.out.println("cloudAudienceUrn: " + cloudAudienceUrn);
				System.out.println("ActiveAuthUrl: " + userRealmResponse.getFederationActiveAuthUrl());
				
				
				// Discover the policy for authentication using the Metadata Exchange Url.
				// Get the WSTrust Token (Web Service Trust Token)
				WSTrustResponse response = WSTrustRequest.execute(mexURL, cloudAudienceUrn, this.proxy,
						this.sslSocketFactory);

				// TODO : need to parse the response to get the SAML assertion token
				// We need to parse the document to get the SAML assertion token
				System.out.println("SAML version of Token: " + response.getTokenType());
				System.out.println("the SAML Assertion token ???: " + response.getToken());
				System.out.println(response.SAML1_ASSERTION);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		
		

		return null;
	}
    
    
    
    
    
    

    private void validateInput(final String resource, final Object credential,
            final boolean validateResource) {
        if (validateResource && StringHelper.isBlank(resource)) {
            throw new IllegalArgumentException("resource is null or empty");
        }
        if (credential == null) {
            throw new IllegalArgumentException("credential is null");
        }
    }

    /**
     * Acquires an access token from the authority on behalf of a user. It
     * requires using a user token previously received.
     *
     * @param resource
     *            Identifier of the target resource that is the recipient of the
     *            requested token.
     * @param userAssertion
     *            userAssertion to use as Authorization grant
     * @param credential
     *            The client credential to use for token acquisition.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token and the Access Token's expiration time. Refresh Token
     *         property will be null for this overload.
     * @throws AuthenticationException {@link AuthenticationException}
     */
    public Future<AuthenticationResult> acquireToken(final String resource,
            final UserAssertion userAssertion, final ClientCredential credential,
            final AuthenticationCallback callback) {

        this.validateInput(resource, credential, true);
        Map<String, String> params = new HashMap<String, String>();
        params.put("resource", resource);
        params.put("requested_token_use", "on_behalf_of");
        try {
            AdalAuthorizatonGrant grant = new AdalAuthorizatonGrant(
                    new JWTBearerGrant(
                            SignedJWT.parse(userAssertion.getAssertion())), params);

            final ClientAuthentication clientAuth = new ClientSecretPost(
                    new ClientID(credential.getClientId()), new Secret(
                            credential.getClientSecret()));
            return this.acquireToken(grant, clientAuth, callback);
        }
        catch (final Exception e) {
            throw new AuthenticationException(e);
        }
    }

    /**
     * Acquires security token from the authority.
     *
     * @param resource
     *            Identifier of the target resource that is the recipient of the
     *            requested token.
     * @param credential
     *            The client credential to use for token acquisition.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token and the Access Token's expiration time. Refresh Token
     *         property will be null for this overload.
     */
    public Future<AuthenticationResult> acquireToken(final String resource,
            final ClientCredential credential,
            final AuthenticationCallback callback) {
        this.validateInput(resource, credential, true);
        final ClientAuthentication clientAuth = new ClientSecretPost(
                new ClientID(credential.getClientId()), new Secret(
                        credential.getClientSecret()));
        final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(
                new ClientCredentialsGrant(), resource);
        return this.acquireToken(authGrant, clientAuth, callback);
    }

    /**
     * Acquires security token from the authority.
     *
     * @param resource
     *            Identifier of the target resource that is the recipient of the
     *            requested token.
     * @param credential
     *            object representing Private Key to use for token acquisition.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token and the Access Token's expiration time. Refresh Token
     *         property will be null for this overload.
     * @throws AuthenticationException {@link AuthenticationException}
     */
    public Future<AuthenticationResult> acquireToken(final String resource,
            final AsymmetricKeyCredential credential,
            final AuthenticationCallback callback)
            throws AuthenticationException {
        return this.acquireToken(resource, JwtHelper.buildJwt(credential,
                this.authenticationAuthority.getSelfSignedJwtAudience()),
                callback);
    }

    /**
     * Acquires security token from the authority using an authorization code
     * previously received.
     *
     * @param authorizationCode
     *            The authorization code received from service authorization
     * @param resource
     *            Identifier of the target resource that is the recipient of the
     *            requested token.
     * @param clientId
     *            The client assertion to use for token acquisition endpoint.
     * @param redirectUri
     *            The redirect address used for obtaining authorization code.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     */
    public Future<AuthenticationResult> acquireTokenByAuthorizationCode(
            final String authorizationCode, final String resource,
            final String clientId, final URI redirectUri,
            final AuthenticationCallback callback) {

        final ClientAuthentication clientAuth = new ClientAuthenticationPost(
                ClientAuthenticationMethod.NONE, new ClientID(clientId));

        this.validateAuthCodeRequestInput(authorizationCode, redirectUri,
                clientAuth, resource);
        final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(
                new AuthorizationCodeGrant(new AuthorizationCode(
                        authorizationCode), redirectUri), resource);
        return this.acquireToken(authGrant, clientAuth, callback);
    }

    /**
     * Acquires security token from the authority using an authorization code
     * previously received.
     *
     * @param authorizationCode
     *            The authorization code received from service authorization
     *            endpoint.
     * @param redirectUri
     *            The redirect address used for obtaining authorization code.
     * @param clientAssertion
     *            The client assertion to use for client authentication.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     */
    public Future<AuthenticationResult> acquireTokenByAuthorizationCode(
            final String authorizationCode, final URI redirectUri,
            final ClientAssertion clientAssertion,
            final AuthenticationCallback callback) {
        return acquireTokenByAuthorizationCode(authorizationCode, redirectUri,
                clientAssertion, (String) null, callback);
    }

    /**
     * Acquires security token from the authority using an authorization code
     * previously received.
     *
     * @param authorizationCode
     *            The authorization code received from service authorization
     *            endpoint.
     * @param redirectUri
     *            The redirect address used for obtaining authorization code.
     * @param clientAssertion
     *            The client assertion to use for client authentication.
     * @param resource
     *            Identifier of the target resource that is the recipient of the
     *            requested token. It can be null if provided earlier to acquire
     *            authorizationCode.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     */
    public Future<AuthenticationResult> acquireTokenByAuthorizationCode(
            final String authorizationCode, final URI redirectUri,
            final ClientAssertion clientAssertion, final String resource,
            final AuthenticationCallback callback) {

        this.validateAuthCodeRequestInput(authorizationCode, redirectUri,
                clientAssertion, resource);
        final ClientAuthentication clientAuth = createClientAuthFromClientAssertion(clientAssertion);
        final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(
                new AuthorizationCodeGrant(new AuthorizationCode(
                        authorizationCode), redirectUri), resource);
        return this.acquireToken(authGrant, clientAuth, callback);
    }

    /**
     * Acquires security token from the authority using an authorization code
     * previously received.
     *
     * @param authorizationCode
     *            The authorization code received from service authorization
     *            endpoint.
     * @param redirectUri
     *            The redirect address used for obtaining authorization code.
     * @param credential
     *            The client credential to use for token acquisition.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     */
    public Future<AuthenticationResult> acquireTokenByAuthorizationCode(
            final String authorizationCode, final URI redirectUri,
            final ClientCredential credential,
            final AuthenticationCallback callback) {
        this.validateAuthCodeRequestInput(authorizationCode, redirectUri,
                credential, null);
        return this.acquireTokenByAuthorizationCode(authorizationCode,
                redirectUri, credential, null, callback);
    }

    /**
     * Acquires security token from the authority using an authorization code
     * previously received.
     *
     * @param authorizationCode
     *            The authorization code received from service authorization
     *            endpoint.
     * @param redirectUri
     *            The redirect address used for obtaining authorization code.
     * @param credential
     *            The client credential to use for token acquisition.
     * @param resource
     *            Identifier of the target resource that is the recipient of the
     *            requested token. It can be null if provided earlier to acquire
     *            authorizationCode.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     */
    public Future<AuthenticationResult> acquireTokenByAuthorizationCode(
            final String authorizationCode, final URI redirectUri,
            final ClientCredential credential, final String resource,
            final AuthenticationCallback callback) {

        this.validateAuthCodeRequestInput(authorizationCode, redirectUri,
                credential, resource);
        final ClientAuthentication clientAuth = new ClientSecretPost(
                new ClientID(credential.getClientId()), new Secret(
                        credential.getClientSecret()));
        final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(
                new AuthorizationCodeGrant(new AuthorizationCode(
                        authorizationCode), redirectUri), resource);
        return this.acquireToken(authGrant, clientAuth, callback);

    }

    /**
     * Acquires security token from the authority using an authorization code
     * previously received.
     *
     * @param authorizationCode
     *            The authorization code received from service authorization
     *            endpoint.
     * @param redirectUri
     *            The redirect address used for obtaining authorization code.
     * @param credential
     *            object representing Private Key to use for token acquisition.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     * @throws AuthenticationException
     *             thrown if {@link AsymmetricKeyCredential} fails to sign the
     *             JWT token.
     */
    public Future<AuthenticationResult> acquireTokenByAuthorizationCode(
            final String authorizationCode, final URI redirectUri,
            final AsymmetricKeyCredential credential,
            final AuthenticationCallback callback)
            throws AuthenticationException {
        return this.acquireTokenByAuthorizationCode(authorizationCode,
                redirectUri, credential, null, callback);
    }

    /**
     * Acquires security token from the authority using an authorization code
     * previously received.
     *
     * @param authorizationCode
     *            The authorization code received from service authorization
     *            endpoint.
     * @param redirectUri
     *            The redirect address used for obtaining authorization code.
     * @param credential
     *            object representing Private Key to use for token acquisition.
     * @param resource
     *            Identifier of the target resource that is the recipient of the
     *            requested token. It can be null if provided earlier to acquire
     *            authorizationCode.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     * @throws AuthenticationException
     *             thrown if {@link AsymmetricKeyCredential} fails to sign the
     *             JWT token.
     */
    public Future<AuthenticationResult> acquireTokenByAuthorizationCode(
            final String authorizationCode, final URI redirectUri,
            final AsymmetricKeyCredential credential, final String resource,
            final AuthenticationCallback callback)
            throws AuthenticationException {
        this.validateAuthCodeRequestInput(authorizationCode, redirectUri,
                credential, resource);
        return this.acquireTokenByAuthorizationCode(authorizationCode,
                redirectUri, JwtHelper
                        .buildJwt(credential, this.authenticationAuthority
                                .getSelfSignedJwtAudience()), resource,
                callback);
    }

    /**
     * Acquires a security token from the authority using a Refresh Token
     * previously received.
     *
     * @param refreshToken
     *            Refresh Token to use in the refresh flow.
     * @param clientId
     *            Name or ID of the client requesting the token.
     * @param clientAssertion
     *            The client assertion to use for client authentication.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     */
    public Future<AuthenticationResult> acquireTokenByRefreshToken(
            final String refreshToken, final String clientId,
            final ClientAssertion clientAssertion,
            final AuthenticationCallback callback) {
        return acquireTokenByRefreshToken(refreshToken, clientId, clientAssertion,
                null, callback);
    }

    /**
     * Acquires a security token from the authority using a Refresh Token
     * previously received.
     *
     * @param refreshToken
     *            Refresh Token to use in the refresh flow.
     * @param clientId
     *            Name or ID of the client requesting the token.
     * @param clientAssertion
     *            The client assertion to use for client authentication.
     * @param resource
     *            Identifier of the target resource that is the recipient of the
     *            requested token. If null, token is requested for the same
     *            resource refresh token was originally issued for. If passed,
     *            resource should match the original resource used to acquire
     *            refresh token unless token service supports refresh token for
     *            multiple resources.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     */
    public Future<AuthenticationResult> acquireTokenByRefreshToken(
            final String refreshToken, final String clientId,
            final ClientAssertion clientAssertion, final String resource,
            final AuthenticationCallback callback) {
        this.validateRefreshTokenRequestInput(refreshToken, clientId,
                clientAssertion);
        final ClientAuthentication clientAuth = createClientAuthFromClientAssertion(clientAssertion);
        final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(
                new RefreshTokenGrant(new RefreshToken(refreshToken)), resource);
        return this.acquireToken(authGrant, clientAuth, callback);
    }

    /**
     * Acquires a security token from the authority using a Refresh Token
     * previously received.
     *
     * @param refreshToken
     *            Refresh Token to use in the refresh flow.
     * @param credential
     *            The client credential used for token acquisition.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     */
    public Future<AuthenticationResult> acquireTokenByRefreshToken(
            final String refreshToken, final ClientCredential credential,
            final AuthenticationCallback callback) {
        return acquireTokenByRefreshToken(refreshToken, credential,
                (String) null, callback);
    }

    /**
     * Acquires a security token from the authority using a Refresh Token
     * previously received.
     *
     * @param refreshToken
     *            Refresh Token to use in the refresh flow.
     * @param credential
     *            The client credential used for token acquisition.
     * @param resource
     *            Identifier of the target resource that is the recipient of the
     *            requested token. If null, token is requested for the same
     *            resource refresh token was originally issued for. If passed,
     *            resource should match the original resource used to acquire
     *            refresh token unless token service supports refresh token for
     *            multiple resources.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     */
    public Future<AuthenticationResult> acquireTokenByRefreshToken(
            final String refreshToken, final ClientCredential credential,
            final String resource, final AuthenticationCallback callback) {

        final ClientAuthentication clientAuth = new ClientSecretPost(
                new ClientID(credential.getClientId()), new Secret(
                        credential.getClientSecret()));
        final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(
                new RefreshTokenGrant(new RefreshToken(refreshToken)), resource);
        return this.acquireToken(authGrant, clientAuth, callback);
    }

    /**
     * Acquires a security token from the authority using a Refresh Token
     * previously received.
     *
     * @param refreshToken
     *            Refresh Token to use in the refresh flow.
     * @param credential
     *            object representing Private Key to use for token acquisition.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     * @throws AuthenticationException
     *             thrown if {@link AsymmetricKeyCredential} fails to sign the
     *             JWT token.
     */
    public Future<AuthenticationResult> acquireTokenByRefreshToken(
            final String refreshToken,
            final AsymmetricKeyCredential credential,
            final AuthenticationCallback callback)
            throws AuthenticationException {
        return acquireTokenByRefreshToken(refreshToken, credential,
                (String) null, callback);
    }

    /**
     * Acquires a security token from the authority using a Refresh Token
     * previously received.
     *
     * @param refreshToken
     *            Refresh Token to use in the refresh flow.
     * @param credential
     *            object representing Private Key to use for token acquisition.
     * @param resource
     *            Identifier of the target resource that is the recipient of the
     *            requested token. If null, token is requested for the same
     *            resource refresh token was originally issued for. If passed,
     *            resource should match the original resource used to acquire
     *            refresh token unless token service supports refresh token for
     *            multiple resources.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     * @throws AuthenticationException
     *             thrown if {@link AsymmetricKeyCredential} fails to sign the
     *             JWT token.
     */
    public Future<AuthenticationResult> acquireTokenByRefreshToken(
            final String refreshToken,
            final AsymmetricKeyCredential credential, final String resource,
            final AuthenticationCallback callback)
            throws AuthenticationException {

        return acquireTokenByRefreshToken(
                refreshToken,
                credential.getClientId(),
                JwtHelper.buildJwt(credential,
                        this.authenticationAuthority.getSelfSignedJwtAudience()),
                (String) null, callback);
    }

    /**
     * Acquires a security token from the authority using a Refresh Token
     * previously received. This method is suitable for the daemon OAuth2
     * flow when a client secret is not possible.
     *
     * @param refreshToken
     *            Refresh Token to use in the refresh flow.
     * @param clientId
     *            Name or ID of the client requesting the token.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     * @throws AuthenticationException
     *             thrown if the access token is not refreshed successfully
     */
    public Future<AuthenticationResult> acquireTokenByRefreshToken(
            final String refreshToken, final String clientId,
            final AuthenticationCallback callback) {

        return acquireTokenByRefreshToken(refreshToken, clientId, (String)null, callback);
    }

    /**
     * Acquires a security token from the authority using a Refresh Token
     * previously received. This method is suitable for the daemon OAuth2
     * flow when a client secret is not possible.
     *
     * @param refreshToken
     *            Refresh Token to use in the refresh flow.
     * @param clientId
     *            Name or ID of the client requesting the token.
     * @param resource
     *            Identifier of the target resource that is the recipient of the
     *            requested token. If null, token is requested for the same
     *            resource refresh token was originally issued for. If passed,
     *            resource should match the original resource used to acquire
     *            refresh token unless token service supports refresh token for
     *            multiple resources.
     * @param callback
     *            optional callback object for non-blocking execution.
     * @return A {@link Future} object representing the
     *         {@link AuthenticationResult} of the call. It contains Access
     *         Token, Refresh Token and the Access Token's expiration time.
     * @throws AuthenticationException
     *             thrown if the access token is not refreshed successfully
     */
    public Future<AuthenticationResult> acquireTokenByRefreshToken(
            final String refreshToken, final String clientId,
            final String resource, final AuthenticationCallback callback) {

        final ClientAuthentication clientAuth = new ClientAuthenticationPost(
                ClientAuthenticationMethod.NONE, new ClientID(clientId));
        final AdalAuthorizatonGrant authGrant = new AdalAuthorizatonGrant(
                new RefreshTokenGrant(new RefreshToken(refreshToken)), resource);
        return this.acquireToken(authGrant, clientAuth, callback);
    }

    private void validateRefreshTokenRequestInput(final String refreshToken,
            final String clientId, final Object credential) {

        if (StringHelper.isBlank(refreshToken)) {
            throw new IllegalArgumentException("refreshToken is null or empty");
        }

        if (StringHelper.isBlank(clientId)) {
            throw new IllegalArgumentException("clientId is null or empty");
        }
        this.validateInput(null, credential, false);
    }

    private AuthenticationResult acquireTokenCommon(
            final AdalAuthorizatonGrant authGrant,
            final ClientAuthentication clientAuth,
            final ClientDataHttpHeaders headers) throws Exception {
        log.debug(LogHelper.createMessage(
                String.format("Using Client Http Headers: %s", headers),
                headers.getHeaderCorrelationIdValue()));
        this.authenticationAuthority.doInstanceDiscovery(
                headers.getReadonlyHeaderMap(), this.proxy,
                this.sslSocketFactory);
        final URL url = new URL(this.authenticationAuthority.getTokenUri());
        final AdalTokenRequest request = new AdalTokenRequest(url, clientAuth,
                authGrant, headers.getReadonlyHeaderMap(), this.proxy,
                this.sslSocketFactory);
        AuthenticationResult result = request
                .executeOAuthRequestAndProcessResponse();
        return result;
    }

    /**
     *
     * @param authGrant
     */
    private AdalAuthorizatonGrant processPasswordGrant(
            AdalAuthorizatonGrant authGrant) throws Exception {

        if (!(authGrant.getAuthorizationGrant() instanceof ResourceOwnerPasswordCredentialsGrant)) {
            return authGrant;
        }

        ResourceOwnerPasswordCredentialsGrant grant = (ResourceOwnerPasswordCredentialsGrant) authGrant
                .getAuthorizationGrant();

        UserDiscoveryResponse userDiscoveryResponse = UserDiscoveryRequest.execute(
                this.authenticationAuthority.getUserRealmEndpoint(grant
                        .getUsername()), this.proxy, this.sslSocketFactory);
        if (userDiscoveryResponse.isAccountFederated()) {
            WSTrustResponse response = WSTrustRequest.execute(
                    userDiscoveryResponse.getFederationMetadataUrl(),
                    grant.getUsername(), grant.getPassword().getValue(), userDiscoveryResponse.getCloudAudienceUrn(),
                    this.proxy, this.sslSocketFactory);

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

            authGrant = new AdalAuthorizatonGrant(updatedGrant,
                    authGrant.getCustomParameters());
        }

        return authGrant;
    }

    private void logResult(AuthenticationResult result,
            ClientDataHttpHeaders headers) throws NoSuchAlgorithmException,
            UnsupportedEncodingException {
        if (!StringHelper.isBlank(result.getAccessToken())) {
            String logMessage = "";
            String accessTokenHash = this.computeSha256Hash(result
                    .getAccessToken());
            if (!StringHelper.isBlank(result.getRefreshToken())) {
                String refreshTokenHash = this.computeSha256Hash(result
                        .getRefreshToken());
                logMessage = String
                        .format("Access Token with hash '%s' and Refresh Token with hash '%s' returned",
                                accessTokenHash, refreshTokenHash);
            }
            else {
                logMessage = String
                        .format("Access Token with hash '%s' returned",
                                accessTokenHash);
            }
            log.debug(LogHelper.createMessage(logMessage,
                    headers.getHeaderCorrelationIdValue()));
        }
    }

    private String computeSha256Hash(String input)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(input.getBytes("UTF-8"));
        byte[] hash = digest.digest();
        return Base64.encodeBase64URLSafeString(hash);
    }

    private ClientAuthentication createClientAuthFromClientAssertion(
            final ClientAssertion clientAssertion) {

        try {
            final Map<String, String> map = new HashMap<String, String>();
            map.put("client_assertion_type", clientAssertion.getAssertionType());
            map.put("client_assertion", clientAssertion.getAssertion());
            return PrivateKeyJWT.parse(map);
        }
        catch (final ParseException e) {
            throw new AuthenticationException(e);
        }
    }

    /**
     * Returns the correlation id configured by the user. It does not return the
     * id automatically generated by the API in case the user does not provide
     * one.
     *
     * @return String value of the correlation id
     */
    public String getCorrelationId() {
        return correlationId;
    }

    /**
     * Set optional correlation id to be used by the API. If not provided, the
     * API generates a random id.
     *
     * @param correlationId
     *            String value
     */
    public void setCorrelationId(final String correlationId) {
        this.correlationId = correlationId;
    }

    /**
     * Returns validateAuthority boolean value passed as a constructor
     * parameter.
     *
     * @return boolean value
     */
    public boolean shouldValidateAuthority() {
        return this.validateAuthority;
    }

    /**
     * Authority associated with the context instance
     *
     * @return String value
     */
    public String getAuthority() {
        return this.authority;
    }

    private void validateAuthCodeRequestInput(final String authorizationCode,
            final URI redirectUri, final Object clientCredential,
            final String resource) {
        if (StringHelper.isBlank(authorizationCode)) {
            throw new IllegalArgumentException(
                    "authorization code is null or empty");
        }

        if (redirectUri == null) {
            throw new IllegalArgumentException("redirect uri is null");
        }

        this.validateInput(resource, clientCredential, false);
    }
}
