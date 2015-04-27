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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class WSTrustRequest {

    private final static Logger log = LoggerFactory
            .getLogger(WSTrustRequest.class);

    private final static int MAX_EXPECTED_MESSAGE_SIZE = 1024;
    private final static String WSTRUST_ENVELOPE_TEMPLATE = "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:a='http://www.w3.org/2005/08/addressing' xmlns:u='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'>"
            + "<s:Header>"
            + "<a:Action s:mustUnderstand='1'>http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action>"
            + "<a:messageID>urn:uuid:%s</a:messageID>"
            + "<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
            + "<a:To s:mustUnderstand='1'>%s</a:To>"
            + "%s"
            + "</s:Header>"
            + "<s:Body>"
            + "<trust:RequestSecurityToken xmlns:trust='http://docs.oasis-open.org/ws-sx/ws-trust/200512'>"
            + "<wsp:AppliesTo xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy'>"
            + "<a:EndpointReference>"
            + "<a:Address>%s</a:Address>"
            + "</a:EndpointReference>"
            + "</wsp:AppliesTo>"
            + "<trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType>"
            + "<trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>"
            + "</trust:RequestSecurityToken>" + "</s:Body>" + "</s:Envelope>";

    private final static String DEFAULT_APPLIES_TO = "urn:federation:MicrosoftOnline";

    static WSTrustResponse execute(String url, String username, String password)
            throws Exception {
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/soap+xml; charset=utf-8");
        headers.put("SOAPAction",
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");
        String body = BuildMessage(url, username, password).toString();
        String response = HttpHelper.executeHttpPost(log, url, body, headers);
        return WSTrustResponse.parse(response);
    }

    private static StringBuilder BuildMessage(String resource, String username,
            String password) {
        StringBuilder securityHeaderBuilder = BuildSecurityHeader(username,
                password);
        String guid = UUID.randomUUID().toString();
        StringBuilder messageBuilder = new StringBuilder(
                MAX_EXPECTED_MESSAGE_SIZE);
        messageBuilder.append(String.format(WSTRUST_ENVELOPE_TEMPLATE, guid,
                resource, securityHeaderBuilder, DEFAULT_APPLIES_TO));
        return messageBuilder;
    }

    private static StringBuilder BuildSecurityHeader(String username, String password) {

        StringBuilder securityHeaderBuilder = new StringBuilder(
                MAX_EXPECTED_MESSAGE_SIZE);

        StringBuilder messageCredentialsBuilder = new StringBuilder(
                MAX_EXPECTED_MESSAGE_SIZE);
        String guid = UUID.randomUUID().toString();

        messageCredentialsBuilder
                .append(String
                        .format("<o:UsernameToken u:Id='uuid-%s'><o:Username>%s</o:Username><o:Password>%s</o:Password></o:UsernameToken>",
                                guid, username, password));

        DateFormat dateFormat = new SimpleDateFormat(
                "yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date date = new Date();
        String currentTimeString = dateFormat.format(date);

        // Expiry is 10 minutes after creation
        int toAdd = 60 * 1000 * 10;
        date = new Date(date.getTime() + toAdd);
        String expiryTimString = dateFormat.format(date);

        securityHeaderBuilder
                .append(String
                        .format("<o:Security s:mustUnderstand='1' "
                                + "xmlns:o='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'>"
                                + "<u:Timestamp u:Id='_0'><u:Created>%s</u:Created>"
                                + "<u:Expires>%s</u:Expires></u:Timestamp>%s</o:Security>",
                                currentTimeString, expiryTimString,
                                messageCredentialsBuilder));

        return securityHeaderBuilder;
    }

}
