package com.microsoft.aad.adal4j;

import java.util.Map;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;

public class SamlCredentialGrant extends AuthorizationGrant {
	
	private Map<String, String> parameters;
	public SamlCredentialGrant(GrantType grantType, Map<String,String> parameters) {
		super(grantType);
		this.parameters = parameters;
	}
	@Override
	public Map<String, String> toParameters() {
		return this.parameters;
	}

}
