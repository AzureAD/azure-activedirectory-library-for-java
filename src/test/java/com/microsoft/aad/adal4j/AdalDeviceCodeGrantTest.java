package com.microsoft.aad.adal4j;


import java.util.Map;

import org.testng.Assert;
import org.testng.annotations.Test;

public class AdalDeviceCodeGrantTest {

    @Test
    public void testConstructor() {
        final DeviceCode deviceCode = new DeviceCode(
                "", "", "", 0, 0, "");
        final AdalDeviceCodeGrant deviceCodeGrant = new AdalDeviceCodeGrant(
                deviceCode, "");
        Assert.assertNotNull(deviceCodeGrant);
    }

    @Test
    public void testToParameters() {
        final String code = "test-code";
        final String resource = "https://test";
        final DeviceCode deviceCode = new DeviceCode(
                "", code, "", 0, 0, "");
        final AdalDeviceCodeGrant deviceCodeGrant = new AdalDeviceCodeGrant(
                deviceCode, resource);
        Assert.assertNotNull(deviceCodeGrant);

        Map<String, String> params = deviceCodeGrant.toParameters();
        Assert.assertNotNull(params);
        Assert.assertEquals(params.get("grant_type"), "device_code");
        Assert.assertEquals(params.get("resource"), resource);
        Assert.assertEquals(params.get("code"), code);
    }
}