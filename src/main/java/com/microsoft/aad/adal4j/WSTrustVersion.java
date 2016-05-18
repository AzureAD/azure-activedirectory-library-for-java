/**
 * *****************************************************************************
 * Copyright © Microsoft Open Technologies, Inc.
 *
 * All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED
 * WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
 * MERCHANTABILITY OR NON-INFRINGEMENT.
 *
 * See the Apache License, Version 2.0 for the specific language governing
 * permissions and limitations under the License.
 * ****************************************************************************
 */
package com.microsoft.aad.adal4j;

enum WSTrustVersion {

    WSTRUST13(
            "//s:Envelope/s:Body/wst:RequestSecurityTokenResponseCollection/wst:RequestSecurityTokenResponse/wst:TokenType",
            "wst:RequestedSecurityToken"), WSTRUST2005(
            "//s:Envelope/s:Body/t:RequestSecurityTokenResponse/t:TokenType",
            "t:RequestedSecurityToken"), UNDEFINED("", "");
    private String responseTokenTypePath = "";
    private String responseSecurityTokenPath = "";

    WSTrustVersion(String tokenType, String responseSecurityToken) {
        this.responseTokenTypePath = tokenType;
        this.responseSecurityTokenPath = responseSecurityToken;
    }

    public String getResponseTokenTypePath() {
        return this.responseTokenTypePath;
    }

    public String getResponseSecurityTokenPath() {
        return this.responseSecurityTokenPath;
    }
}
