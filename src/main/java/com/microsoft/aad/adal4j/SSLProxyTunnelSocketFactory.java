// sample was written based on https://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/samples/sockets/client/SSLSocketClientWithTunneling.java
// here is the copyright notice:

/*
 *
 * Copyright (c) 1994, 2004, Oracle and/or its affiliates. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * -Redistribution of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistribution in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the
 * distribution.
 *
 * Neither the name of Oracle nor the names of
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * This software is provided "AS IS," without a warranty of any
 * kind. ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND
 * WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT, ARE HEREBY
 * EXCLUDED. SUN MICROSYSTEMS, INC. ("SUN") AND ITS LICENSORS SHALL
 * NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT
 * OF USING, MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS
 * DERIVATIVES. IN NO EVENT WILL SUN OR ITS LICENSORS BE LIABLE FOR
 * ANY LOST REVENUE, PROFIT OR DATA, OR FOR DIRECT, INDIRECT,
 * SPECIAL, CONSEQUENTIAL, INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER
 * CAUSED AND REGARDLESS OF THE THEORY OF LIABILITY, ARISING OUT OF
 * THE USE OF OR INABILITY TO USE THIS SOFTWARE, EVEN IF SUN HAS
 * BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 *
 * You acknowledge that this software is not designed, licensed or
 * intended for use in the design, construction, operation or
 * maintenance of any nuclear facility.
 */

// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package com.microsoft.aad.adal4j;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * Supports proxy tunneling with authentication.
 */
public class SSLProxyTunnelSocketFactory extends SSLSocketFactory {
    private SSLSocketFactory defaultFactory;

    private String tunnelHost;

    private int tunnelPort;

    private ChallengeHandler challengeHandler;

    /**
     * Creates an SSLProxyTunnelSocketFactory for proxy tunneling.
     *
     * @param proxyHost the host of the proxy
     * @param proxyPort the port of the proxy
     * @param challengeHandler the handler to handle authentication challenges
     */
    public SSLProxyTunnelSocketFactory(String proxyHost, int proxyPort, ChallengeHandler challengeHandler) {
        tunnelHost = proxyHost;
        tunnelPort = proxyPort;
        defaultFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();

        this.challengeHandler = challengeHandler;
    }

    public Socket createSocket(String host, int port) throws IOException {
        return createSocket(null, host, port, true);
    }

    public Socket createSocket(String host, int port, InetAddress clientHost,
                               int clientPort) throws IOException {
        return createSocket(null, host, port, true);
    }

    public Socket createSocket(InetAddress host, int port) throws IOException {
        return createSocket(null, host.getHostName(), port, true);
    }

    public Socket createSocket(InetAddress address, int port,
                               InetAddress clientAddress, int clientPort) throws IOException {
        return createSocket(null, address.getHostName(), port, true);
    }

    public Socket createSocket(Socket s, String host, int port,
                               boolean autoClose) throws IOException {
        Socket tunnel = new Socket(tunnelHost, tunnelPort);

        PrintStream out = new PrintStream(tunnel.getOutputStream());

        out.println("CONNECT " + host + ":" + port + " HTTP/1.1");
        out.println("User-Agent: Adal4j");
        out.print("\r\n");

        out.flush();
        String response = getResponse(tunnel);

        if (response.toLowerCase().contains("http/1.1 407")) {
            out.println("CONNECT " + host + ":" + port + " HTTP/1.1");
            out.println("User-Agent: Adal4j");
            List<String> headers = new ArrayList<>();

            for (String header : response.split("\\n")) {
                if (header.toLowerCase().startsWith("proxy-authenticate")) {
                    headers.add(header.replaceFirst("[pP]roxy-[aA]uthenticate:", "").trim());
                }
            }
            out.println("Proxy-Authorization: " + challengeHandler.handle("CONNECT", host + ":" + port, headers));
            out.print("\r\n");

            out.flush();

            response = getResponse(tunnel);
        }

        if (!response.toLowerCase().contains("http/1.1 200")) {
            throw new IOException(String.format("Failed to establish tunnel %s:%d. Message: %s",
                    tunnelHost, tunnelPort, response));
        }

        SSLSocket result = (SSLSocket) defaultFactory.createSocket(tunnel, host,
                port, autoClose);

        return result;
    }

    public String[] getDefaultCipherSuites() {
        return defaultFactory.getDefaultCipherSuites();
    }

    public String[] getSupportedCipherSuites() {
        return defaultFactory.getSupportedCipherSuites();
    }

    private String getResponse(Socket tunnel) throws IOException {
        StringBuilder replyStr = new StringBuilder();

        InputStream in = tunnel.getInputStream();

        Scanner scan = new Scanner(in);

        while(scan.hasNextLine()){
            String line = scan.nextLine();
            if (line.isEmpty()) {
                break;
            } else {
                replyStr.append(line).append("\n");
            }
        }

        return replyStr.toString();
    }
}
