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

import javax.net.ssl.SSLSocketFactory;
import java.net.Proxy;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class UserDiscoveryRequest {

    private final static Logger log = LoggerFactory
            .getLogger(UserDiscoveryRequest.class);
    private final static Map<String, String> HEADERS;
    static {
        HEADERS = new HashMap<>();
        HEADERS.put("Accept", "application/json, text/javascript, */*");

    }

    static UserDiscoveryResponse execute(final String uri, final Proxy proxy,
            final SSLSocketFactory sslSocketFactory) throws Exception {

        String response = HttpHelper.executeHttpGet(log, uri, HEADERS, proxy,
                sslSocketFactory);
        return JsonHelper.convertJsonToObject(response,
                UserDiscoveryResponse.class);
    }
}
