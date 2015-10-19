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

import com.google.gson.annotations.SerializedName;

class UserDiscoveryResponse {

    @SerializedName("ver")
    private float version;

    @SerializedName("account_type")
    private String accountType;

    @SerializedName("federation_metadata_url")
    private String federationMetadataUrl;

    @SerializedName("federation_protocol")
    private String federationProtocol;

    @SerializedName("federation_active_auth_url")
    private String federationActiveAuthUrl;

    float getVersion() {
        return version;
    }

    boolean isAccountFederated() {
        return !StringHelper.isBlank(this.accountType)
                && this.accountType.equalsIgnoreCase("Federated");
    }

    String getFederationProtocol() {
        return federationProtocol;
    }

    String getFederationMetadataUrl() {
        return federationMetadataUrl;
    }

    String getFederationActiveAuthUrl() {
        return federationActiveAuthUrl;
    }
}
