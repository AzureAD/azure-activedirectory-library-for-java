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
package com.microsoft.azure.interactiveauthclientsample;

import java.net.URI;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.naming.ServiceUnavailableException;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.interactive.PromptBehavior;

public class App 
{
	private static final String RESOURCE = "https://management.core.windows.net/";
	private final static String AUTHORITY = "https://login.windows.net/common";
    private final static String CLIENT_ID = "61d65f5a-6e3b-468b-af73-a033f5098c5c";
	private static final String REDIRECT_URI = "https://msopentech.com/";
	
    public static void main( String[] args )
    {
		try {
			AuthenticationResult result;
			result = getAccessTokenInteractive();
			System.out.println("Access Token - " + result.getAccessToken());
	        System.out.println("Refresh Token - " + result.getRefreshToken());
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		System.exit(0);
    }
    
    private static AuthenticationResult getAccessTokenInteractive() throws Exception {
        AuthenticationContext context = null;
        AuthenticationResult result = null;
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            context = new AuthenticationContext(AUTHORITY, false, service);
            Future<AuthenticationResult> future = context.acquireToken(
            		RESOURCE, CLIENT_ID,
            		new URI(REDIRECT_URI), "Sign in to your account",
            		PromptBehavior.LOGIN, null);
            result = future.get();
        } finally {
            service.shutdown();
        }

        if (result == null) {
            throw new ServiceUnavailableException(
                    "authentication result was null");
        }
        return result;
    }
}
