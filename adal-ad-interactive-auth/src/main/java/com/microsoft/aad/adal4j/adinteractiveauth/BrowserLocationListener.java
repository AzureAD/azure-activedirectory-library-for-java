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

import com.google.common.base.Splitter;
import org.eclipse.swt.browser.LocationAdapter;
import org.eclipse.swt.browser.LocationEvent;

import java.net.URI;
import java.util.Map;

public class BrowserLocationListener extends LocationAdapter {
    private AuthCodeCallback callback;
    private String redirectUri;

    public BrowserLocationListener(String redirectUri, AuthCodeCallback callback) {
        this.redirectUri = redirectUri;
        this.callback = callback;
    }

    @Override
    public void changing(LocationEvent locationEvent) {
        super.changing(locationEvent);

        // if the location matches the redirect uri then extract
        // the auth code and cancel the navigation and invoke the
        // callback
        if(locationEvent.location.startsWith(redirectUri)) {
            locationEvent.doit = false;
            URI uri = URI.create(locationEvent.location);
            Map<String, String> response = Splitter.on('&').
                    trimResults().
                    omitEmptyStrings().
                    withKeyValueSeparator('=').
                    split(uri.getQuery());
            if(response.containsKey("code")) {
                callback.onAuthCodeReceived(response.get("code"));
            } else {
                callback.onFailed(uri.getQuery());
            }
        }
    }
}
