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
package com.microsoft.adal4j;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import org.easymock.EasyMock;
import org.powermock.api.easymock.PowerMock;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;

/**
 *
 */
@Test(groups = { "checkin" })
public class UserInfoTest extends AbstractAdalTests {

    @Test
    public void testCreateFromIdTokenClaims_EmptyClaims() throws ParseException {

        final ReadOnlyJWTClaimsSet claimSet = PowerMock
                .createMock(ReadOnlyJWTClaimsSet.class);
        EasyMock.expect(claimSet.getAllClaims())
                .andReturn(new HashMap<String, Object>()).times(1);
        EasyMock.replay(claimSet);
        Assert.assertNull(UserInfo.createFromIdTokenClaims(claimSet));
        PowerMock.verifyAll();
    }

    @Test
    public void testCreateFromIdTokenClaims_Null() throws ParseException {

        Assert.assertNull(UserInfo.createFromIdTokenClaims(null));
    }

    @Test
    public void testCreateFromIdTokenClaims_HasEmail() throws ParseException {

        final ReadOnlyJWTClaimsSet claimSet = PowerMock
                .createMock(ReadOnlyJWTClaimsSet.class);
        final Map<String, Object> map = new HashMap<String, Object>();
        map.put("", "");
        EasyMock.expect(claimSet.getAllClaims()).andReturn(map).times(1);
        EasyMock.expect(
                claimSet.getStringClaim(AuthenticationConstants.ID_TOKEN_UPN))
                .andReturn(null).times(1);
        EasyMock.expect(
                claimSet.getStringClaim(AuthenticationConstants.ID_TOKEN_EMAIL))
                .andReturn("test@value.com").times(2);
        EasyMock.expect(
                claimSet.getStringClaim(AuthenticationConstants.ID_TOKEN_GIVEN_NAME))
                .andReturn("test").times(1);
        EasyMock.expect(
                claimSet.getStringClaim(AuthenticationConstants.ID_TOKEN_FAMILY_NAME))
                .andReturn("value").times(1);
        EasyMock.expect(
                claimSet.getStringClaim(AuthenticationConstants.ID_TOKEN_IDENTITY_PROVIDER))
                .andReturn("idp").times(1);

        EasyMock.replay(claimSet);
        final UserInfo ui = UserInfo.createFromIdTokenClaims(claimSet);
        Assert.assertNotNull(ui);
        Assert.assertEquals("test@value.com", ui.getUserId());
        Assert.assertTrue(ui.isUserIdDisplayable());
        Assert.assertEquals("test", ui.getGivenName());
        Assert.assertEquals("value", ui.getFamilyName());
        Assert.assertEquals("idp", ui.getIdentityProvider());
        PowerMock.verifyAll();
    }

    @Test
    public void testCreateFromIdTokenClaims_HasSubject() throws ParseException {

        final ReadOnlyJWTClaimsSet claimSet = PowerMock
                .createMock(ReadOnlyJWTClaimsSet.class);
        final Map<String, Object> map = new HashMap<String, Object>();
        map.put("", "");
        EasyMock.expect(claimSet.getAllClaims()).andReturn(map).times(1);
        EasyMock.expect(
                claimSet.getStringClaim(AuthenticationConstants.ID_TOKEN_UPN))
                .andReturn(null).times(1);
        EasyMock.expect(
                claimSet.getStringClaim(AuthenticationConstants.ID_TOKEN_EMAIL))
                .andReturn(null).times(1);
        EasyMock.expect(claimSet.getSubject()).andReturn("test@value.com")
                .times(2);
        EasyMock.expect(
                claimSet.getStringClaim(AuthenticationConstants.ID_TOKEN_GIVEN_NAME))
                .andReturn("test").times(1);
        EasyMock.expect(
                claimSet.getStringClaim(AuthenticationConstants.ID_TOKEN_FAMILY_NAME))
                .andReturn("value").times(1);
        EasyMock.expect(
                claimSet.getStringClaim(AuthenticationConstants.ID_TOKEN_IDENTITY_PROVIDER))
                .andReturn("idp").times(1);

        EasyMock.replay(claimSet);
        final UserInfo ui = UserInfo.createFromIdTokenClaims(claimSet);
        Assert.assertNotNull(ui);
        Assert.assertEquals("test@value.com", ui.getUserId());
        Assert.assertFalse(ui.isUserIdDisplayable());
        Assert.assertEquals("test", ui.getGivenName());
        Assert.assertEquals("value", ui.getFamilyName());
        Assert.assertEquals("idp", ui.getIdentityProvider());
        PowerMock.verifyAll();
    }

}
