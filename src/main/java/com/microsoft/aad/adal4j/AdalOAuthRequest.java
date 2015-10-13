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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Collections;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

/**
 * 
 * 
 */
class AdalOAuthRequest extends HTTPRequest {

    private final Map<String, String> extraHeaderParams;
    private final Logger log = LoggerFactory.getLogger(AdalOAuthRequest.class);

    /**
     * 
     * @param method
     * @param url
     * @param correlationId
     */
    AdalOAuthRequest(final Method method, final URL url,
            final Map<String, String> extraHeaderParams) {
        super(method, url);
        this.extraHeaderParams = extraHeaderParams;
    }

    Map<String, String> getReadOnlyExtraHeaderParameters() {
        return Collections.unmodifiableMap(this.extraHeaderParams);
    }

    /**
     * 
     */
    @Override
    public HTTPResponse send() throws IOException {

        final HttpURLConnection conn = HttpHelper.openConnection(this.getURL());
        this.configureHeaderAndExecuteOAuthCall(conn);
        final String out = this.processAndReadResponse(conn);
        HttpHelper.verifyReturnedCorrelationId(log, conn,
                this.extraHeaderParams
                        .get(ClientDataHttpHeaders.CORRELATION_ID_HEADER_NAME));
        return createResponse(conn, out);
    }

    HTTPResponse createResponse(final HttpURLConnection conn, final String out)
            throws IOException {
        final HTTPResponse response = new HTTPResponse(conn.getResponseCode());
        final String location = conn.getHeaderField("Location");
        if (!StringHelper.isBlank(location)) {
            response.setLocation(new URL(location));
        }

        try {
            response.setContentType(conn.getContentType());
        } catch (final ParseException e) {
            throw new IOException("Couldn't parse Content-Type header: "
                    + e.getMessage(), e);
        }

        response.setCacheControl(conn.getHeaderField("Cache-Control"));
        response.setPragma(conn.getHeaderField("Pragma"));
        response.setWWWAuthenticate(conn.getHeaderField("WWW-Authenticate"));
        if (!StringHelper.isBlank(out)) {
            response.setContent(out);
        }
        return response;
    }

    void configureHeaderAndExecuteOAuthCall(final HttpURLConnection conn)
            throws IOException {

        if (this.getAuthorization() != null) {
            conn.setRequestProperty("Authorization", this.getAuthorization());
        }

        Map<String, String> params = new java.util.HashMap<>();
        if (this.extraHeaderParams != null && !this.extraHeaderParams.isEmpty()) {
            for (java.util.Map.Entry<String, String> entry : this.extraHeaderParams.entrySet()) {
                if (entry.getValue() == null || entry.getValue().isEmpty()) {
                    continue;
                }
                params.put(entry.getKey(), entry.getValue());
            }
        }
        
        HttpHelper.configureAdditionalHeaders(conn, params);
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type",
                CommonContentTypes.APPLICATION_URLENCODED.toString());

        if (this.getQuery() != null) {
            final OutputStreamWriter writer = new OutputStreamWriter(
                    conn.getOutputStream());
            writer.write(getQuery());
            writer.flush();
            writer.close();
        }
    }

    String processAndReadResponse(final HttpURLConnection conn)
            throws IOException {
        Reader inReader = null;
        final int responseCode = conn.getResponseCode();
        if (responseCode == 200) {
            inReader = new InputStreamReader(conn.getInputStream());
        } else {
        	InputStream stream = conn.getErrorStream();
        	if(stream == null && responseCode == 404)
        	{
        		stream = conn.getInputStream();
        	}
        	
            inReader = new InputStreamReader(stream);
        }
        final BufferedReader reader = new BufferedReader(inReader);
        final char[] buffer = new char[256];
        final StringBuilder out = new StringBuilder();
        try {
            for (;;) {
                final int rsz = reader.read(buffer, 0, buffer.length);
                if (rsz < 0) {
                    break;
                }
                out.append(buffer, 0, rsz);
            }
        } finally {
            reader.close();
        }
        return out.toString();
    }
}
