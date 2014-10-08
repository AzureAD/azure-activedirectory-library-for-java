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

import java.util.HashMap;
import java.util.Map;

import javax.mail.internet.ContentType;

import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.URLUtils;

class ClientAuthenticationPost extends ClientAuthentication {

    protected ClientAuthenticationPost(ClientAuthenticationMethod method,
            ClientID clientID) {
        super(method, clientID);
    }

    Map<String, String> toParameters() {

        Map<String, String> params = new HashMap<String, String>();

        params.put("client_id", getClientID().getValue());

        return params;
    }

    @Override
    public void applyTo(HTTPRequest httpRequest) throws SerializeException {

        if (httpRequest.getMethod() != HTTPRequest.Method.POST)
            throw new SerializeException("The HTTP request method must be POST");

        ContentType ct = httpRequest.getContentType();

        if (ct == null)
            throw new SerializeException("Missing HTTP Content-Type header");

        if (!ct.match(CommonContentTypes.APPLICATION_URLENCODED))
            throw new SerializeException(
                    "The HTTP Content-Type header must be "
                            + CommonContentTypes.APPLICATION_URLENCODED);

        Map<String, String> params = httpRequest.getQueryParameters();

        params.putAll(toParameters());

        String queryString = URLUtils.serializeParameters(params);

        httpRequest.setQuery(queryString);

    }

}
