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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

import org.easymock.EasyMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.Test;

@Test(groups = { "checkin" })
@PrepareForTest({ RSAPrivateKey.class })
public class AsymmetricKeyCredentialTest extends AbstractAdalTests {

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "clientId is null or empty")
    public void testNullClientId() {
        AsymmetricKeyCredential.create(null, (PrivateKey) null, null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "clientId is null or empty")
    public void testEmptyClientId() {
        AsymmetricKeyCredential.create("", (PrivateKey) null, null);
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "PrivateKey")
    public void testNullKey() {
        AsymmetricKeyCredential.create("id", (PrivateKey) null, null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "certificate key size must be at least 2048")
    public void testInvalidKeysize() {
        final RSAPrivateKey key = EasyMock.createMock(RSAPrivateKey.class);
        final BigInteger modulus = EasyMock.createMock(BigInteger.class);
        EasyMock.expect(modulus.bitLength()).andReturn(2047).times(1);
        EasyMock.expect(key.getModulus()).andReturn(modulus).times(1);
        EasyMock.replay(modulus, key);
        AsymmetricKeyCredential.create("id", key, null);
    }

    @Test
    public void testGetClient() {
        final RSAPrivateKey key = EasyMock.createMock(RSAPrivateKey.class);
        final BigInteger modulus = EasyMock.createMock(BigInteger.class);
        EasyMock.expect(modulus.bitLength()).andReturn(2048).times(1);
        EasyMock.expect(key.getModulus()).andReturn(modulus).times(1);
        EasyMock.replay(modulus, key);
        final AsymmetricKeyCredential kc = AsymmetricKeyCredential.create("id", key, null);
        assertNotNull(kc);
        assertEquals("id", kc.getClientId());
    }

    @Test
    public void testGetKey() {
        final RSAPrivateKey key = EasyMock.createMock(RSAPrivateKey.class);
        final BigInteger modulus = EasyMock.createMock(BigInteger.class);
        EasyMock.expect(modulus.bitLength()).andReturn(2048).times(1);
        EasyMock.expect(key.getModulus()).andReturn(modulus).times(1);
        EasyMock.replay(modulus, key);
        final AsymmetricKeyCredential kc = AsymmetricKeyCredential.create("id", key, null);
        assertNotNull(kc);
        assertEquals(key, kc.getKey());
    }
}
