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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.testng.Assert;
import org.testng.annotations.Test;

@Test(groups = { "checkin" })
public class DeviceCodeTest {

    private final String DEVICE_CODE_JSON_FILE = "/devicecode.json";

    private JSONObject getDeviceCodeJson() throws IOException, ParseException {
        try (InputStream is = new FileInputStream(this.getClass()
                .getResource(DEVICE_CODE_JSON_FILE)
                .getFile())) {
            JSONParser parser = new JSONParser(JSONParser.MODE_PERMISSIVE);
            return (JSONObject) parser.parse(is);
        }
    }

    @Test
    public void testConstructor() {
        DeviceCode deviceCode = new DeviceCode("test", "test", "test", 0, 0, "test");
        Assert.assertNotNull(deviceCode);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorNullArgument() {
        new DeviceCode(null, null, null, 0, 0, null);
    }

    @Test
    public void testParseJsonObject() throws IOException, ParseException, com.nimbusds.oauth2.sdk.ParseException {
        JSONObject deviceCodeJson = getDeviceCodeJson();
        DeviceCode deviceCode = DeviceCode.parse(deviceCodeJson);
        Assert.assertNotNull(deviceCode);

        Assert.assertEquals(deviceCode.getUserCode(), JSONObjectUtils.getString(deviceCodeJson, "user_code"));
        Assert.assertEquals(deviceCode.getDeviceCode(), JSONObjectUtils.getString(deviceCodeJson, "device_code"));
        Assert.assertEquals(deviceCode.getVerificationUrl(), JSONObjectUtils.getString(deviceCodeJson, "verification_url"));
        long expiresIn = Long.valueOf(JSONObjectUtils.getString(deviceCodeJson, "expires_in"));
        Assert.assertEquals(deviceCode.getExpiresIn(), expiresIn);
        long interval = Long.valueOf(JSONObjectUtils.getString(deviceCodeJson, "interval"));
        Assert.assertEquals(deviceCode.getInterval(), interval);
        Assert.assertEquals(deviceCode.getMessage(), JSONObjectUtils.getString(deviceCodeJson, "message"));
    }

    @Test(expectedExceptions = com.nimbusds.oauth2.sdk.ParseException.class)
    public void testParseEmptyDeviceCode() throws com.nimbusds.oauth2.sdk.ParseException {
        JSONObject deviceCodeJson = new JSONObject();
        DeviceCode.parse(deviceCodeJson);
    }
}
