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

import com.google.gson.annotations.SerializedName;

public final class DeviceCode {

    /**
     *  The user code.
     */
    @SerializedName("user_code")
    private String userCode;

    /**
     * The device code.
     */
    @SerializedName("device_code")
    private String deviceCode;

    /**
     * The verification url.
     */
    @SerializedName("verification_url")
    private String verificationUrl;

    /**
     * The expiration time in seconds.
     */
    @SerializedName("expires_in")
    private long expiresIn;

    /**
     * The interval
     */
    @SerializedName("interval")
    private long interval;

    /**
     * The message which should be displayed to the user.
     */
    @SerializedName("message")
    private String message;

    private transient  String correlationId = null;

    private transient  String clientId = null;

    private transient  String resource = null;

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

    protected String getCorrelationId() {
        return correlationId;
    }

    protected void setCorrelationId(String correlationId) {
        this.correlationId = correlationId;
    }

    protected String getClientId() {
        return clientId;
    }

    protected void setClientId(String clientId) {
        this.clientId = clientId;
    }

    protected String getResource() {
        return resource;
    }

    protected void setResource(String resource) {
        this.resource = resource;
    }
}
