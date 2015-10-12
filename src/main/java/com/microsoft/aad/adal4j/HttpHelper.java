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
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.util.Map;

import org.slf4j.Logger;

class HttpHelper {

    static String executeHttpGet(final Logger log, final String url)
            throws Exception {
        return executeHttpGet(log, url, null, null);
    }

    static String executeHttpGet(final Logger log, final String url, final Proxy proxy)
            throws Exception {
        return executeHttpGet(log, url, null, proxy);
    }

    static String executeHttpGet(final Logger log, final String url,
            final Map<String, String> headers) throws Exception {
        final HttpURLConnection conn = HttpHelper.openConnection(url);
        return executeGetRequest(log, headers, conn);
    }

    static String executeHttpGet(final Logger log, final String url,
                                 final Map<String, String> headers, final Proxy proxy) throws Exception {
        final HttpURLConnection conn =
                    proxy == null ?
                            HttpHelper.openConnection(url) :
                            HttpHelper.openConnection(url, proxy);
        return executeGetRequest(log, headers, conn);
    }

    static String executeHttpPost(final Logger log, final String url,
            String postData) throws Exception {
        return executeHttpPost(log, url, postData, null);
    }

    static String executeHttpPost(final Logger log, final String url,
            String postData, final Map<String, String> headers)
            throws Exception {
        final HttpURLConnection conn = HttpHelper.openConnection(url);
        return executePostRequest(log, postData, headers, conn);
    }

    static String executeHttpPost(final Logger log, final String url,
                                  String postData, final Map<String, String> headers, final Proxy proxy)
            throws Exception {
        final HttpURLConnection conn =
                    proxy == null ?
                            HttpHelper.openConnection(url) :
                            HttpHelper.openConnection(url, proxy);
        return executePostRequest(log, postData, headers, conn);
    }

    static String readResponseFromConnection(final HttpURLConnection conn)
            throws IOException {
        final Reader inReader = new InputStreamReader(conn.getInputStream());
        final BufferedReader reader = new BufferedReader(inReader);
        final char[] buffer = new char[256];
        final StringBuilder out = new StringBuilder();
        try {
            if (conn.getResponseCode() != 200) {
                throw new IOException("Failed: HTTP error code "
                        + conn.getResponseCode());
            }

            int rsz = -1;
            while ((rsz = reader.read(buffer, 0, buffer.length)) > -1) {
                out.append(buffer, 0, rsz);
            }
        } finally {
            reader.close();
        }

        return out.toString();
    }

    static HttpURLConnection openConnection(final URL finalURL, final Proxy proxy)
            throws IOException  {
        return (HttpURLConnection) finalURL.openConnection(proxy);
    }

    static HttpURLConnection openConnection(final URL finalURL)
            throws IOException {
        return (HttpURLConnection) finalURL.openConnection();
    }

    static HttpURLConnection openConnection(final String url, final Proxy proxy)
            throws IOException {
        return openConnection(new URL(url), proxy);
    }

    static HttpURLConnection openConnection(final String url)
            throws IOException {
        return openConnection(new URL(url));
    }

    static HttpURLConnection configureAdditionalHeaders(
            final HttpURLConnection conn, final Map<String, String> headers)
            throws MalformedURLException, IOException {
        if (headers != null) {
            for (final String key : headers.keySet()) {
                conn.setRequestProperty(key, headers.get(key));
            }
        }
        return conn;
    }

    static void verifyReturnedCorrelationId(Logger log, HttpURLConnection conn,
            String sentCorrelationId) {
        if (StringHelper
                .isBlank(conn
                        .getHeaderField(ClientDataHttpHeaders.CORRELATION_ID_HEADER_NAME))
                || !conn.getHeaderField(
                        ClientDataHttpHeaders.CORRELATION_ID_HEADER_NAME)
                        .equals(sentCorrelationId)) {
            log.info(LogHelper.createMessage(
                    String.format(
                            "Sent (%s) Correlation Id is not same as received (%s).",
                            sentCorrelationId,
                            conn.getHeaderField(ClientDataHttpHeaders.CORRELATION_ID_HEADER_NAME)),
                    sentCorrelationId));
        }
    }

    private static String executeGetRequest(Logger log, Map<String, String> headers, HttpURLConnection conn)
            throws IOException {
        configureAdditionalHeaders(conn, headers);
        return getResponse(log, headers, conn);
    }

    private static String executePostRequest(Logger log, String postData, Map<String, String> headers,
                                             HttpURLConnection conn) throws IOException {
        configureAdditionalHeaders(conn, headers);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        DataOutputStream wr = null;
        try {
            wr = new DataOutputStream(conn.getOutputStream());
            wr.writeBytes(postData);
            wr.flush();

            return getResponse(log, headers, conn);
        } finally {
            if (wr != null) {
                wr.close();
            }
        }
    }

    private static String getResponse(Logger log, Map<String, String> headers, HttpURLConnection conn)
            throws IOException {
        String response = readResponseFromConnection(conn);
        if (headers != null) {
            HttpHelper.verifyReturnedCorrelationId(log, conn, headers
                    .get(ClientDataHttpHeaders.CORRELATION_ID_HEADER_NAME));
        }
        return response;
    }
}
