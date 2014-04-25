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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 *
 */
final class ClientDataHttpHeaders {

    public final static String PRODUCT_HEADER_NAME = "x-client-SKU";
    public final static String PRODUCT_HEADER_VALUE = "java";

    public final static String PRODUCT_VERSION_HEADER_NAME = "x-client-VER";
    public final static String PRODUCT_VERSION_HEADER_VALUE = getProductVersion();

    public final static String CPU_HEADER_NAME = "x-client-CPU";
    public final static String CPU_HEADER_VALUE = System.getProperty("os.arch");

    public final static String OS_HEADER_NAME = "x-client-OS";
    public final static String OS_HEADER_VALUE = System.getProperty("os.name");

    public final static String CORRELATION_ID_HEADER_NAME = "client-request-id";
    public final String correlationIdHeaderValue;

    public final static String REQUEST_CORRELATION_ID_IN_RESPONSE_HEADER_NAME = "return-client-request-id";
    public final static String REQUEST_CORRELATION_ID_IN_RESPONSE_HEADER_VALUE = "true";
    private final String headerValues;
    private final Map<String, String> headerMap = new HashMap<String, String>();

    ClientDataHttpHeaders(final String correlationId) {
        if (!StringHelper.isBlank(correlationId)) {
            this.correlationIdHeaderValue = correlationId;
        } else {
            this.correlationIdHeaderValue = UUID.randomUUID().toString();
        }
        this.headerValues = initHeaderMap();
    }

    private String initHeaderMap() {
        StringBuilder sb = new StringBuilder();
        headerMap.put(PRODUCT_HEADER_NAME, PRODUCT_HEADER_VALUE);
        sb.append(PRODUCT_HEADER_NAME);
        sb.append("=");
        sb.append(PRODUCT_HEADER_VALUE);
        sb.append(";");
        headerMap
                .put(PRODUCT_VERSION_HEADER_NAME, PRODUCT_VERSION_HEADER_VALUE);
        sb.append(PRODUCT_VERSION_HEADER_NAME);
        sb.append("=");
        sb.append(PRODUCT_VERSION_HEADER_VALUE);
        sb.append(";");
        headerMap.put(OS_HEADER_NAME, OS_HEADER_VALUE);
        sb.append(OS_HEADER_NAME);
        sb.append("=");
        sb.append(OS_HEADER_VALUE);
        sb.append(";");
        headerMap.put(CPU_HEADER_NAME, CPU_HEADER_VALUE);
        sb.append(CPU_HEADER_NAME);
        sb.append("=");
        sb.append(CPU_HEADER_VALUE);
        sb.append(";");
        headerMap.put(REQUEST_CORRELATION_ID_IN_RESPONSE_HEADER_NAME,
                REQUEST_CORRELATION_ID_IN_RESPONSE_HEADER_VALUE);
        sb.append(REQUEST_CORRELATION_ID_IN_RESPONSE_HEADER_NAME);
        sb.append("=");
        sb.append(REQUEST_CORRELATION_ID_IN_RESPONSE_HEADER_VALUE);
        sb.append(";");
        headerMap
                .put(CORRELATION_ID_HEADER_NAME, this.correlationIdHeaderValue);
        sb.append(CORRELATION_ID_HEADER_NAME);
        sb.append("=");
        sb.append(this.correlationIdHeaderValue);
        sb.append(";");

        return sb.toString();
    }

    Map<String, String> getReadonlyHeaderMap() {
        return Collections.unmodifiableMap(this.headerMap);
    }

    String getHeaderCorrelationIdValue() {
        return this.correlationIdHeaderValue;
    }

    @Override
    public String toString() {
        return this.headerValues;
    }

    private static String getProductVersion() {
        if (ClientDataHttpHeaders.class.getPackage().getImplementationVersion() == null) {
            return "1.0";
        }
        return ClientDataHttpHeaders.class.getPackage()
                .getImplementationVersion();
    }
}
