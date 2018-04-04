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
        Assert.assertEquals(aa.getDeviceCodeEndpoint(),
                TestConfiguration.AAD_TENANT_ENDPOINT + "oauth2/devicecode");
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
        Assert.assertEquals(aa.getDeviceCodeEndpoint(),
                TestConfiguration.ADFS_TENANT_ENDPOINT + "oauth2/devicecode");
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
