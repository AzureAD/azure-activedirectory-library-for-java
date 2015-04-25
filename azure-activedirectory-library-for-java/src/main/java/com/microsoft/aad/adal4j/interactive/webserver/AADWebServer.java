/**
 * Copyright 2014 Microsoft Open Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.microsoft.aad.adal4j.interactive.webserver;

import com.google.common.io.ByteStreams;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

public class AADWebServer extends WebServer {
    private static final String STATUS_SUCCESS = "success";
    private static final String AUTH_PATH = "/auth";
    private static final String CLOSED_PATH = "/closed";
    private static final String STATUS_PARAM_NAME = "status";
    private static final String DATA_PARAM_NAME = "data";
    private AuthCodeCallback authCodeCallback;
    private ClosedCallback closedCallback;

    public AADWebServer() throws IOException {
        super(-1);

        // setup request handlers
        get(AUTH_PATH, new AuthRequestHandler());
        get(CLOSED_PATH, new ClosedRequestHandler());
    }

    @Override
    public URL getBaseURL() throws MalformedURLException {
        return new URL(super.getBaseURL(), AUTH_PATH);
    }

    public void setAuthCodeCallback(AuthCodeCallback authCodeCallback) {
        this.authCodeCallback = authCodeCallback;
    }

    public void setClosedCallback(ClosedCallback closedCallback) {
        this.closedCallback = closedCallback;
    }

    class AuthRequestHandler implements HttpHandler {
        private String code;

		@Override
        public void handle(HttpExchange httpExchange) throws IOException {
            Map<String, String> params = URLUtils.parseParameters(httpExchange.getRequestURI().getQuery());

            if(params == null ||
               !params.containsKey(STATUS_PARAM_NAME) ||
               !params.containsKey(DATA_PARAM_NAME) ||
               !params.get(STATUS_PARAM_NAME).equals(STATUS_SUCCESS)) {

                httpExchange.sendResponseHeaders(400, -1);
                if(authCodeCallback != null) {
                    authCodeCallback.onAuthCodeReceived(null, params);
                }
                return;
            }

            code = params.get(DATA_PARAM_NAME);

            // setup response headers
            Headers headers = httpExchange.getResponseHeaders();
            headers.add("Content-Type", "text/html");
            httpExchange.sendResponseHeaders(200, 0);

            // send browser response
            try {
				OutputStream output = httpExchange.getResponseBody();
				output.write(new String("<h1>Code received.</h1>").getBytes());
				output.close();
			} catch (Exception ignored) {}

            // raise the notification for the code
            if(authCodeCallback != null) {
                authCodeCallback.onAuthCodeReceived(code, params);
            }
        }

        public String getCode() {
            return code;
        }
    }

    class ClosedRequestHandler implements  HttpHandler {

        @Override
        public void handle(HttpExchange httpExchange) throws IOException {
            if(closedCallback != null) {
                closedCallback.onClosed();
            }

            httpExchange.sendResponseHeaders(200, -1);
        }
    }
}
