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
 * Credential type containing user realm 
 */
public final class UserRealm {

    private String apiVersion;
    private String federationProtocol;
    private String accountType;
    private String federationMetadataUrl; 
    private String federationActiveAuthUrl;

    public UserRealm() {
    }

    public String getApiVersion() {
        return apiVersion;
    }
    public UserRealm setApiVersion(String apiVersion)
    {
    	this.apiVersion = apiVersion;
    	return this;
    }
    public String getFederationProtocol() {
        return federationProtocol;
    }
    
    public UserRealm setFederationProtocol(String federationProtocol)
    {
    	this.federationProtocol = federationProtocol;
    	return this;
    }
    
    public String getAccountType() {
    	return accountType;
    }
    
    public UserRealm setAccountType(String accountType)
    {
    	this.accountType = accountType;
    	return this;
    }

    public String getFederationMetadataUrl() {
    	return federationMetadataUrl;
    }
    
    public UserRealm setFederationMetadataUrl(String federationMetadataUrl)
    {
    	this.federationMetadataUrl = federationMetadataUrl;
    	return this;
    }
    
    public String getFederationActiveAuthUrl(){
    	return federationActiveAuthUrl;
    }
    
    public UserRealm setFederationActiveAuthUrl(String federationActiveAuthUrl)
    {
    	this.federationActiveAuthUrl = federationActiveAuthUrl;
    	return this;
    }

}
