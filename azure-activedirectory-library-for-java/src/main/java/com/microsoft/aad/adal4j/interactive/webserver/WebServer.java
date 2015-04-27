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

import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.*;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;

public class WebServer {
    protected Map<String, HttpContext> routes = new HashMap<String, HttpContext>();
    private int port;
    protected HttpServer server;
    private final ExecutorService pool;
    private boolean running = false;
    private final ReentrantLock lock = new ReentrantLock();

    protected final int STOP_WAIT_DELAY = 0;
    private static final int POOL_SIZE = 10;

    public WebServer(int port) throws IOException {
        this.port = (port == -1) ? getUnusedLocalPort() : port;
        server = HttpServer.create(new InetSocketAddress(this.port), 0);
        pool = Executors.newFixedThreadPool(POOL_SIZE);
        server.setExecutor(pool);
    }

    private int getUnusedLocalPort() throws IOException {
        ServerSocket socket = null;
        try {
            socket = new ServerSocket(0);
            return socket.getLocalPort();
        }
        finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    public URL getBaseURL() throws MalformedURLException {
        return new URL("http://localhost:" + String.valueOf(port) + "/");
    }

    public WebServer request(String path, HttpHandler handler) {
        HttpContext context = server.createContext(path, handler);
        routes.put(path, context);
        return this;
    }

    public WebServer get(String path, final HttpHandler handler) {
        return request(path, new HttpHandler() {
            @Override
            public void handle(HttpExchange httpExchange) throws IOException {
                // check if the request method is "GET"
                if(httpExchange.getRequestMethod().compareToIgnoreCase("GET") != 0) {
                    // send a 405 Method Not Allowed error
                    httpExchange.sendResponseHeaders(405, 0);
                } else {
                    handler.handle(httpExchange);
                }
            }
        });
    }

    public void start() {
        server.start();

        lock.lock();
        try {
            running = true;
        }
        finally {
            lock.unlock();
        }
    }

    public void stop() {
        server.stop(STOP_WAIT_DELAY);
        running = false;
    }

    public Map<String, HttpContext> getRoutes() {
        return routes;
    }

    public int getPort() {
        return port;
    }

    public boolean isRunning() {
        return running;
    }
}
