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

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

/**
 *  Device code returned by Azure Active Directory
 *
 *  <p> Example device code serialized to JSON:
 *   <pre>
 *   {
 *      "user_code": "DW83JNP2P",
 *      "device_code": "DAQABAAEAAADRNYRQ3dhRSrm-4K-adpCJ0D4JzelxlksQioyRVsCC0nWL7wqK0KPxDaF-g9WmI5cAyjVGWF6kZMUyd6E0LZbo2zzJ02e6CyTS_jV5hBRlyqJtpQ-r562GCkEzal3PdYab9qFFEeqWvq-yipsIeD5lryOnxb1CKF2I6QodK2pb1iAA",
 *      "verification_url": "https://aka.ms/devicelogin",
 *      "expires_in": "900",
 *      "interval": "5",
 *      "message": "To sign in, use a web browser to open the page https://aka.ms/devicelogin and enter the code DW83JNP2P to authenticate."
 *   }
 *   </pre>
 */
@Immutable
public final class DeviceCode implements JSONAware {

    /**
     *  The user code.
     */
    private final String userCode;

    /**
     * The device code.
     */
    private final String deviceCode;

    /**
     * The verification url.
     */
    private final String verificationUrl;

    /**
     * The expiration time in seconds.
     */
    private final long expiresIn;

    /**
     * The interval
     */
    private final long interval;

    /**
     * The message which should be displayed to the user.
     */
    private final String message;

    /**
     * Creates a new Device Code
     *
     * @param userCode         The user code.
     * @param deviceCode       The device code.
     * @param verificationUrl  The verification URL.
     * @param expiresIn        The expiration time in seconds.
     * @param interval         The interval.
     * @param message          The message which should be displayed to the user.
     */
    public DeviceCode(final String userCode,
                      final String deviceCode,
                      final String verificationUrl,
                      final long expiresIn,
                      final long interval,
                      final String message) {
        if (userCode == null) {
            throw new IllegalArgumentException("The use code must not be null");
        }
        if (deviceCode == null) {
            throw new IllegalArgumentException("The device code must not be null");
        }
        if (verificationUrl == null) {
            throw new IllegalArgumentException("The verification URL must not be null");
        }
        if (message == null) {
            throw new IllegalArgumentException("The message must not be null");
        }

        this.userCode = userCode;
        this.deviceCode = deviceCode;
        this.verificationUrl = verificationUrl;
        this.expiresIn = expiresIn;
        this.interval = interval;
        this.message = message;
    }

    /**
     * Creates a new Device Code.
     *
     * @param deviceCode The Device Code as string
     */
    public DeviceCode(final String deviceCode) {
        this.deviceCode = deviceCode;
        this.userCode = null;
        this.verificationUrl = null;
        this.expiresIn = 0;
        this.interval = 0;
        this.message = null;
    }

    /**
     * Returns the user code.
     *
     * @return The user code.
     */
    public String getUserCode() {
        return userCode;
    }

    /**
     * Returns the device code.
     *
     * @return The device code.
     */
    public String getDeviceCode() {
        return deviceCode;
    }

    /**
     * Returns the verification URL.
     *
     * @return The verification URL.
     */
    public String getVerificationUrl() {
        return verificationUrl;
    }

    /**
     * Returns the expiration in seconds.
     *
     * @return The expiration time in seconds.
     */
    public long getExpiresIn() {
        return expiresIn;
    }

    /**
     * Returns the interval.
     *
     * @return The interval.
     */
    public long getInterval() {
        return interval;
    }

    /**
     * Returns the message which should be displayed to the user.
     *
     * @return The message.
     */
    public String getMessage() {
        return message;
    }

    /**
     * Returns the device code serialized as a JSON object.
     *
     * @return The device code as JSONObject.
     */
    public JSONObject toJSONObject() {
        JSONObject o = new JSONObject();

        o.put("user_code", userCode);
        o.put("device_code", deviceCode);
        o.put("verification_url", verificationUrl);
        o.put("expires_in", expiresIn);
        o.put("interval", interval);
        o.put("message", message);

        return o;
    }

    /**
     * Returns the device code serialized as JSON string.
     *
     * @return The device code as JSON string.
     */
    @Override
    public String toJSONString() {
        return toJSONObject().toString();
    }

    /**
     * Parses a device code from a JSON object.
     *
     * @param jsonObject The JSON object to parse.
     *
     * @return The device code.
     *
     * @throws ParseException If the JSON object couldn't be parsed to a device code.
     */
    public static DeviceCode parse(final JSONObject jsonObject) throws ParseException {
        String userCode = JSONObjectUtils.getString(jsonObject, "user_code");
        String deviceCode = JSONObjectUtils.getString(jsonObject, "device_code");
        String verificationUrl = JSONObjectUtils.getString(jsonObject, "verification_url");
        long expiresIn = Long.valueOf(JSONObjectUtils.getString(jsonObject, "expires_in"));
        long interval = Long.valueOf(JSONObjectUtils.getString(jsonObject, "interval"));
        String message = JSONObjectUtils.getString(jsonObject, "message");
        return new DeviceCode(userCode, deviceCode, verificationUrl, expiresIn, interval, message);
    }
}
