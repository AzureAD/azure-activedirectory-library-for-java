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

import com.nimbusds.jose.util.Base64;

import java.net.*;
import java.io.*;
import javax.net.ssl.*;


/**
 * SSLSocketFactory for tunneling ssl sockets through a proxy with Basic Authorization
 */
public class SSLTunnelSocketFactory extends SSLSocketFactory {
    private SSLSocketFactory defaultFactory;

    private String tunnelHost;

    private int tunnelPort;

    private String proxyUserName;

    private String proxyPassword;

    public SSLTunnelSocketFactory(String proxyHost, String proxyPort,
                                  String proxyUserName, String proxyPassword) {
        tunnelHost = proxyHost;
        tunnelPort = Integer.parseInt(proxyPort);
        defaultFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();

        this.proxyUserName = proxyUserName;
        this.proxyPassword = proxyPassword;
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

        doTunnelHandshake(tunnel, host, port);

        SSLSocket result = (SSLSocket) defaultFactory.createSocket(tunnel, host,
                port, autoClose);

        return result;
    }

    private void doTunnelHandshake(Socket tunnel, String host, int port)
            throws IOException {
        OutputStream out = tunnel.getOutputStream();

        String token = proxyUserName + ":" + proxyPassword;
        String authString = "Basic " + Base64.encode(token.getBytes());

        String msg = "CONNECT " + host + ":" + port + " HTTP/1.1\n"
                + "User-Agent: " + sun.net.www.protocol.http.HttpURLConnection.userAgent + "\n"
                + "Proxy-Authorization: " + authString
                + "\r\n\r\n";

        out.write(msg.getBytes("UTF-8"));
        out.flush();


        StringBuilder replyStr = new StringBuilder();
        int newlinesSeen = 0;
        boolean headerDone = false; /* Done on first newline */

        InputStream in = tunnel.getInputStream();

        while (newlinesSeen < 2) {
            int i = in.read();
            if (i < 0) {
                throw new IOException("Unexpected EOF from proxy");
            }
            if (i == '\n') {
                headerDone = true;
                ++newlinesSeen;
            } else if (i != '\r') {
                newlinesSeen = 0;
                if (!headerDone) {
                    replyStr.append((char) i);
                }
            }
        }

        if (replyStr.toString().toLowerCase().indexOf("200 connection established") == -1) {
            throw new IOException("Unable to tunnel through " + tunnelHost
                    + ":" + tunnelPort + ".  Proxy returns \"" + replyStr + "\"");
        }
    }

    public String[] getDefaultCipherSuites() {
        return defaultFactory.getDefaultCipherSuites();
    }

    public String[] getSupportedCipherSuites() {
        return defaultFactory.getSupportedCipherSuites();
    }
}