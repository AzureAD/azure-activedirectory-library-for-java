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

import java.net.MalformedURLException;
import java.net.URL;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.Test;

@Test(groups = { "checkin" })
@PrepareForTest({ AuthenticationAuthority.class, HttpHelper.class,
        JsonHelper.class, InstanceDiscoveryResponse.class })
public class AuthenticationAuthorityTest extends AbstractAdalTests{

    @Test
    public void testDetectAuthorityType_AAD() throws Exception {
        final AuthenticationAuthority aa = new AuthenticationAuthority(new URL(
                TestConfiguration.AAD_TENANT_ENDPOINT), true);
        Assert.assertEquals(aa.detectAuthorityType(), AuthorityType.AAD);
    }

    @Test
    public void testDetectAuthorityType_ADFS() throws Exception {
        final AuthenticationAuthority aa = new AuthenticationAuthority(new URL(
                TestConfiguration.ADFS_TENANT_ENDPOINT), false);
        Assert.assertEquals(aa.detectAuthorityType(), AuthorityType.ADFS);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "'authority' Uri should have at least one segment in the path \\(i.e. https://<host>/<path>/...\\)")
    public void testConstructor_NoPathAuthority() throws MalformedURLException {
        new AuthenticationAuthority(new URL("https://something.com/"), true);

    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "authority")
    public void testConstructor_NullAuthority() throws Exception {
        new AuthenticationAuthority(null, false);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = AuthenticationErrorMessage.AUTHORITY_URI_INSECURE)
    public void testConstructor_HttpAuthority() throws MalformedURLException {
        new AuthenticationAuthority(new URL("http://I.com/not/h/t/t/p/s/"),
                false);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "authority is invalid format \\(contains fragment\\)")
    public void testConstructor_UrlHasFragment() throws MalformedURLException {
        new AuthenticationAuthority(new URL("https://I.com/something/#haha"),
                true);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "authority cannot contain query parameters")
    public void testConstructor_AuthorityHasQuery()
            throws MalformedURLException {
        new AuthenticationAuthority(new URL(
                "https://I.com/not/?query=not-allowed"), true);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = AuthenticationErrorMessage.UNSUPPORTED_AUTHORITY_VALIDATION)
    public void testConstructor_UnsupportedAuthority()
            throws MalformedURLException {
        new AuthenticationAuthority(new URL(
                TestConfiguration.ADFS_TENANT_ENDPOINT), true);
    }

    @Test
    public void testConstructor_AADAuthority() throws MalformedURLException {
        final AuthenticationAuthority aa = new AuthenticationAuthority(new URL(
                TestConfiguration.AAD_TENANT_ENDPOINT), true);
        Assert.assertNotNull(aa);
        Assert.assertEquals(aa.getAuthority(),
                TestConfiguration.AAD_TENANT_ENDPOINT);
        Assert.assertEquals(aa.getHost(), TestConfiguration.AAD_HOST_NAME);
        Assert.assertEquals(aa.getIssuer(),
                TestConfiguration.AAD_TENANT_ENDPOINT + "oauth2/token");
        Assert.assertEquals(aa.getSelfSignedJwtAudience(),
                TestConfiguration.AAD_TENANT_ENDPOINT + "oauth2/token");
        Assert.assertEquals(aa.getTokenEndpoint(),
                TestConfiguration.AAD_TENANT_ENDPOINT + "oauth2/token");
        Assert.assertEquals(aa.getAuthorityType(), AuthorityType.AAD);
        Assert.assertEquals(aa.getTokenUri(),
                TestConfiguration.AAD_TENANT_ENDPOINT + "oauth2/token");
        Assert.assertEquals(aa.isTenantless(), false);
    }

    @Test
    public void testConstructor_ADFSAuthority() throws MalformedURLException {
        final AuthenticationAuthority aa = new AuthenticationAuthority(new URL(
                TestConfiguration.ADFS_TENANT_ENDPOINT), false);
        Assert.assertNotNull(aa);
        Assert.assertEquals(aa.getAuthority(),
                TestConfiguration.ADFS_TENANT_ENDPOINT);
        Assert.assertEquals(aa.getHost(), TestConfiguration.ADFS_HOST_NAME);
        Assert.assertEquals(aa.getIssuer(),
                TestConfiguration.ADFS_TENANT_ENDPOINT + "oauth2/token");
        Assert.assertEquals(aa.getSelfSignedJwtAudience(),
                TestConfiguration.ADFS_TENANT_ENDPOINT + "oauth2/token");
        Assert.assertEquals(aa.getTokenEndpoint(),
                TestConfiguration.ADFS_TENANT_ENDPOINT + "oauth2/token");
        Assert.assertEquals(aa.getAuthorityType(), AuthorityType.ADFS);
        Assert.assertEquals(aa.getTokenUri(),
                TestConfiguration.ADFS_TENANT_ENDPOINT + "oauth2/token");
        Assert.assertEquals(aa.isTenantless(), false);
    }

    @Test
    public void testDoStaticInstanceDiscovery_ValidateTrue_TrustedAuthority()
            throws MalformedURLException, Exception {
        final AuthenticationAuthority aa = new AuthenticationAuthority(new URL(
                TestConfiguration.AAD_TENANT_ENDPOINT), true);
        Assert.assertTrue(aa.doStaticInstanceDiscovery());

    }

    @Test
    public void testDoStaticInstanceDiscovery_ValidateTrue_UntrustedAuthority()
            throws MalformedURLException, Exception {
        final AuthenticationAuthority aa = new AuthenticationAuthority(new URL(
                TestConfiguration.AAD_UNKNOWN_TENANT_ENDPOINT), true);
        Assert.assertFalse(aa.doStaticInstanceDiscovery());

    }

    @Test
    public void testDoStaticInstanceDiscovery_ValidateFalse_TrustedAuthority()
            throws MalformedURLException, Exception {
        final AuthenticationAuthority aa = new AuthenticationAuthority(new URL(
                TestConfiguration.AAD_UNKNOWN_TENANT_ENDPOINT), false);
        Assert.assertTrue(aa.doStaticInstanceDiscovery());

    }
}
