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

/**
 * Indicates whether acquireToken should automatically prompt only if necessary or whether
 * it should prompt regardless of whether there is a cached token.
 */
public enum PromptBehavior {
    /**
     * Acquire token will prompt the user for credentials only when necessary.  If a token
     * that meets the requirements is already cached then the user will not be prompted.
     */
    AUTO,

    /**
     * The user will be prompted for credentials even if there is a token that meets the requirements
     * already in the cache.
     */
    ALWAYS,

    /**
     * The user will not be prompted for credentials.  If prompting is necessary then the acquireToken request
     * will fail.
     */
    NEVER,

    /**
     * Not yet implemented. Reserved for future use.
     */
    /*
     * Re-authorizes (through displaying browser) the resource usage, making sure that the resulting access
     * token contains updated claims. If user logon cookies are available, the user will not be asked for
     * credentials again and the logon dialog will dismiss automatically.
     */
    REFRESH_SESSION,
    ;
}
