package com.microsoft.aad.adal4j;

import java.util.HashMap;
import java.util.Map;

import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.URLUtils;

public class PublicClientAuthentication extends ClientAuthentication {

	private String clientAssertion;

	public PublicClientAuthentication(ClientID clientID, String clientAssertion) {
		super(ClientAuthenticationMethod.NONE, clientID);
		this.clientAssertion = clientAssertion;
	}

	@Override
	public void applyTo(HTTPRequest httpRequest) throws SerializeException {
		httpRequest.getQueryParameters();
		String body = createBody();
		httpRequest.setQuery(body);
	}

	private String createBody() {
		Map<String,String> parameters = new HashMap<String,String>();
		
		String body = URLUtils.serializeParameters(parameters);
		return body;
	}

}
