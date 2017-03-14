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

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Class for device code grant.
 */
public class AdalDeviceCodeGrant implements AdalGrant {

    private final String GRANT_TYPE = "device_code";

    private final DeviceCode deviceCode;
    private final Map<String, String> params;

    /**
     *  Create a new device code grant object from a device code and a resource.
     *
     * @param deviceCode  The device code.
     * @param resource    The resource for which the device code was acquired.
     */
    AdalDeviceCodeGrant(final DeviceCode deviceCode, final String resource) {
        this.deviceCode = deviceCode;
        params = new LinkedHashMap<>();
        if (!StringHelper.isBlank(resource)) {
            params.put("resource", resource);
        }
    }

    /**
     * Creates a new device code grant object from a device code and some parameters.
     *
     * @param deviceCode The device code.
     * @param params     The map with paramters.
     */
    AdalDeviceCodeGrant(final DeviceCode deviceCode, final Map<String, String> params) {
        this.deviceCode = deviceCode;
        this.params = params;
    }

    /**
     * Converts the device code grant to a map of HTTP paramters.
     *
     * @return The map with HTTP parameters.
     */
    @Override
    public Map<String, String> toParameters() {
        final Map<String, String> outParams = new LinkedHashMap<>();
        outParams.putAll(this.params);

        outParams.put("grant_type", GRANT_TYPE);
        outParams.put("code", deviceCode.getDeviceCode());

        return outParams;
    }

    /**
     * Returns the device code.
     *
     * @return The device code.
     */
    public DeviceCode getDeviceCode() {
        return deviceCode;
    }

    /**
     * Returns a map with HTTP parameters.
     *
     * @return The HTTP parameters.
     */
    public Map<String, String> getParams() {
        return params;
    }
}
