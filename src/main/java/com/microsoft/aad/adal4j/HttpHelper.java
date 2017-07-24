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

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.util.Map;

import org.slf4j.Logger;

class HttpHelper {

    static String executeHttpGet(final Logger log, final String url,
            final Proxy proxy, final SSLSocketFactory sslSocketFactory)
            throws Exception {
        return executeHttpGet(log, url, null, proxy, sslSocketFactory);
    }

    static String executeHttpGet(final Logger log, final String url,
            final Map<String, String> headers, final Proxy proxy,
            final SSLSocketFactory sslSocketFactory) throws Exception {
        final HttpsURLConnection conn = HttpHelper.openConnection(url, proxy,
                sslSocketFactory);
        return executeGetRequest(log, headers, conn);
    }

    static String executeHttpPost(final Logger log, final String url,
            String postData, final Proxy proxy,
            final SSLSocketFactory sslSocketFactory) throws Exception {
        return executeHttpPost(log, url, postData, null, proxy,
                sslSocketFactory);
    }

    static String executeHttpPost(final Logger log, final String url,
            String postData, final Map<String, String> headers,
            final Proxy proxy, final SSLSocketFactory sslSocketFactory)
            throws Exception {
        final HttpsURLConnection conn = HttpHelper.openConnection(url, proxy,
                sslSocketFactory);
        return executePostRequest(log, postData, headers, conn);
    }

    static String inputStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }

    static String readResponseFromConnection(final HttpsURLConnection conn)
            throws AuthenticationException, IOException {
        InputStream is = null;
        try {
            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
                String msg = "Server returned HTTP response code: " + conn.getResponseCode() + " for URL : " +
                        conn.getURL();
                is = conn.getErrorStream();
                if (is != null) {
                    msg = msg + ", Error details : " + inputStreamToString(is);
                }
                throw new AuthenticationException(msg);
            }

            is = conn.getInputStream();
            return inputStreamToString(is);
        }
        finally {
            if(is != null){
                is.close();
            }
        }
    }

    static HttpsURLConnection openConnection(final URL finalURL,
            final Proxy proxy, final SSLSocketFactory sslSocketFactory)
            throws IOException {
        HttpsURLConnection connection;
        if (proxy != null) {
            connection = (HttpsURLConnection) finalURL.openConnection(proxy);
        }
        else {
            connection = (HttpsURLConnection) finalURL.openConnection();
        }

        if (sslSocketFactory != null) {
            connection.setSSLSocketFactory(sslSocketFactory);
        }

        return connection;
    }

    static HttpsURLConnection openConnection(final String url,
            final Proxy proxy, final SSLSocketFactory sslSocketFactory)
            throws IOException {
        return openConnection(new URL(url), proxy, sslSocketFactory);
    }

    static HttpsURLConnection configureAdditionalHeaders(
            final HttpsURLConnection conn, final Map<String, String> headers)
            throws IOException {
        if (headers != null) {
            for (final Map.Entry<String, String> entry : headers.entrySet()) {
                conn.setRequestProperty(entry.getKey(), entry.getValue());
            }
        }
        return conn;
    }

    static void verifyReturnedCorrelationId(Logger log,
            HttpsURLConnection conn, String sentCorrelationId) {
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

    private static String executeGetRequest(Logger log,
            Map<String, String> headers, HttpsURLConnection conn)
            throws IOException {
        configureAdditionalHeaders(conn, headers);
        return getResponse(log, headers, conn);
    }

    private static String executePostRequest(Logger log, String postData,
            Map<String, String> headers, HttpsURLConnection conn)
            throws IOException {
        configureAdditionalHeaders(conn, headers);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        DataOutputStream wr = null;
        try {
            wr = new DataOutputStream(conn.getOutputStream());
            wr.writeBytes(postData);
            wr.flush();

            return getResponse(log, headers, conn);
        }
        finally {
            if (wr != null) {
                wr.close();
            }
        }
    }

    private static String getResponse(Logger log, Map<String, String> headers,
            HttpsURLConnection conn) throws IOException {
        String response = readResponseFromConnection(conn);
        if (headers != null) {
            HttpHelper.verifyReturnedCorrelationId(log, conn, headers
                    .get(ClientDataHttpHeaders.CORRELATION_ID_HEADER_NAME));
        }
        return response;
    }
}
