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

package com.microsoft.aad.adal4j.adinteractiveauth;

import org.eclipse.swt.SWT;
import org.eclipse.swt.SWTError;
import org.eclipse.swt.browser.Browser;
import org.eclipse.swt.graphics.Rectangle;
import org.eclipse.swt.layout.FillLayout;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.MessageBox;
import org.eclipse.swt.widgets.Monitor;
import org.eclipse.swt.widgets.Shell;

import java.awt.*;
import java.io.IOException;
import java.net.*;

public class Program {
    public static void main(String[] args) {
        // we expect the following arguments to be passed in:
        //  [1] a/d login URL
        //  [2] redirect URI
        //  [3] callback url to which the auth code needs to be sent
        //  [4] window title text
        //  [5] optional boolean indicating whether we should invoke System.exit once done
        if(args.length < 4) {
            return;
        }

        String url = args[0];
        String redirectUri = args[1];
        final String callbackUrl = args[2];
        String windowTitle = args[3];
        boolean shouldExit = (args.length > 4) && Boolean.parseBoolean(args[4]);

        Display display = new Display();
        Shell shell = new Shell(display);
        shell.setText(windowTitle);
        Browser browser = null;
        ADAuthCodeCallback authCodeCallback = new ADAuthCodeCallback(display, callbackUrl);

        shell.setLayout(new FillLayout());
        Monitor monitor = display.getPrimaryMonitor();
        Rectangle bounds = monitor.getBounds();
        Dimension size = new Dimension((int) (bounds.width * 0.25), (int) (bounds.height * 0.55));
        shell.setSize(size.width, size.height);
        shell.setLocation((bounds.width - size.width) / 2, (bounds.height - size.height) / 2);

        try {
            browser = new org.eclipse.swt.browser.Browser(shell, SWT.NONE);
        } catch (SWTError err) {
            authCodeCallback.onFailed(
                    "Unable to load the browser component on this system. Here's some additional information: \n" +
                    err.getMessage());
            return;
        }

        BrowserLocationListener locationListener = new BrowserLocationListener(
                redirectUri, authCodeCallback);
        browser.addLocationListener(locationListener);
        browser.setUrl(url);

        shell.open();
        while (!shell.isDisposed()) {
            if (!display.readAndDispatch()) {
                display.sleep();
            }
        }

        display.dispose();

        // notify the caller that the window was closed
        try {
            httpRequest(new URI(callbackUrl).resolve("closed").toURL());
        }
        catch (IOException ignored) {}
        catch (URISyntaxException ignored) {}

        if(shouldExit) {
            System.exit(0);
        }
    }

    private static void showError(Shell shell, String msg) {
        MessageBox msgBox = new MessageBox(shell, SWT.ICON_ERROR);
        msgBox.setMessage(msg);
        msgBox.setText("Error");
        msgBox.open();
    }

    private static void httpRequest(URL url) throws IOException {
        HttpURLConnection connection = (HttpURLConnection)url.openConnection();
        connection.getResponseCode();
    }

    private static class ADAuthCodeCallback implements AuthCodeCallback {
        private final Display display;
        private final String callbackUrl;

        public ADAuthCodeCallback(Display display, String callbackUrl) {
            this.display = display;
            this.callbackUrl = callbackUrl;
        }

        public void onAuthCodeReceived(String authCode) {
            sendStatus("success", "data=" + authCode);
            display.close();
        }

        public void onFailed(String msg) {
            sendStatus("failed", msg);
            display.close();
        }

        private void sendStatus(String status, String data) {
            try {
                httpRequest(new URL(callbackUrl + "?" +
                        URLEncoder.encode(String.format("status=%s&%s", status, data), "UTF-8")));
            } catch (MalformedURLException e) {
                // we shouldn't get here; if we do, well, too bad!
                Program.showError(display.getActiveShell(), e.getMessage());
            } catch (IOException e) {
                // if we get here then it probably means that the user closed the IDE or the
                // web server in the IDE died somehow
                Program.showError(display.getActiveShell(),
                        "Unable to connect to the IDE. Please restart the IDE and retry authentication.");
            }
        }
    }
}
