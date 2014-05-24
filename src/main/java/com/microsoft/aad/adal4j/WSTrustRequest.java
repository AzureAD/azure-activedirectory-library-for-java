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

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;

/**
 * Credential type containing username password.
 */
public final class WSTrustRequest {


	private URL wsTrustEndpointUrl;
	private String appliesTo = "urn:federation:MicrosoftOnline";
	
	private String soapMessageCredentialTemplate = "<wsse:UsernameToken wsu:Id=\'ADALUsernameToken\'>"
        +"<wsse:Username> %s </wsse:Username>"
        +"<wsse:Password> %s </wsse:Password>"
        +"</wsse:UsernameToken>";
	
	private final String RSTTemplate = "<s:Envelope xmlns:s=\'http://www.w3.org/2003/05/soap-envelope\' xmlns:wsa=\'http://www.w3.org/2005/08/addressing\' xmlns:wsu=\'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\'>"
      +"<s:Header>"
      +"<wsa:Action s:mustUnderstand=\'1\'>http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</wsa:Action>"
      +"<wsa:messageID>urn:uuid: %s </wsa:messageID>"
      +"<wsa:ReplyTo>"
          +"<wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address>"
        +"</wsa:ReplyTo>"
        +"<wsa:To s:mustUnderstand=\'1\'> %s </wsa:To> %s"
        + "</s:Header>"
      +"<s:Body>"
        +"<wst:RequestSecurityToken xmlns:wst=\'http://docs.oasis-open.org/ws-sx/ws-trust/200512\'>"
        +"<wsp:AppliesTo xmlns:wsp=\'http://schemas.xmlsoap.org/ws/2004/09/policy\'>"
           +"<wsa:EndpointReference>"
             +"<wsa:Address> %s </wsa:Address>"
           +"</wsa:EndpointReference>"
          +"</wsp:AppliesTo>"
          +"<wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</wst:KeyType>"
          +"<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>"
        +"</wst:RequestSecurityToken>"
      +"</s:Body>"
    +"</s:Envelope>";
	
	private final String securityHeaderXmlTemplate = "<wsse:Security s:mustUnderstand=\'1\' xmlns:wsse=\'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\'>"
        +"<wsu:Timestamp wsu:Id=\'_0\'>"
        +"<wsu:Created> %s </wsu:Created>"
        +"<wsu:Expires> %s </wsu:Expires>"
    +"</wsu:Timestamp>%s</wsse:Security>";
	private Map<String,String> headers = new HashMap<String,String>();

    public WSTrustRequest(URL wsTrustEndpointUrl) {
        this.wsTrustEndpointUrl = wsTrustEndpointUrl;
        this.headers.put("Content-Type", "application/soap+xml; charaset=utf-8");
        this.headers.put("SOAPAction", "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");
        this.headers.put("client-request-id", UUID.randomUUID().toString());
        this.headers.put("return-client-request-id", "true");
    }

    public String acquireToken(String username, String password, AuthenticationCallback authenticationCallback) {
    	String accessToken = "accessToken";
    	HttpURLConnection httpUrlConnection = null;
        try {
			httpUrlConnection = HttpHelper.openConnection(this.wsTrustEndpointUrl);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        sendRequest(httpUrlConnection, username, password);
        WSTrustResponse wsTrustResponse = WSTrustResponse.processResponse(httpUrlConnection);
		return accessToken;
    	
    }
    private void sendRequest(HttpURLConnection httpUrlConnection, String username, String password) {
    	String RST = buildRST(username, password);

    	try {
			HttpHelper.configureAdditionalHeaders(httpUrlConnection, headers);
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	httpUrlConnection.setDoOutput(true);
        OutputStreamWriter writer = null;
		try {
			writer = new OutputStreamWriter(
			    httpUrlConnection.getOutputStream());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
		try {
		    writer.write(RST);
	    } catch (IOException e) {
		    // TODO Auto-generated catch block
	    	e.printStackTrace();
		}
        try {
			writer.flush();
		} catch (IOException e) {
		    // TODO Auto-generated catch block
			e.printStackTrace();
		}
            
        try {
	        writer.close();
		} catch (IOException e) {
		    // TODO Auto-generated catch block
			e.printStackTrace();
		}
        
	}

	private String buildRST(String username, String password) {
    	UUID messageId = UUID.randomUUID();
		String RST = String.format(RSTTemplate, messageId, wsTrustEndpointUrl, buildSecurityHeader(username, password), appliesTo);
		
		return RST;
	}

	private String buildSecurityHeader(String username, String password) {
		Calendar now = Calendar.getInstance();
		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm.SSS");
		TimeZone timeZone = TimeZone.getTimeZone("UTC");
		dateFormat.setTimeZone(timeZone);
		String timeNowString = dateFormat.format(now.getTime())+"Z";
		Calendar expireTime = now;
		expireTime.add(Calendar.MINUTE, 10);
		String expireTimeString =dateFormat.format(expireTime.getTime())+"Z"; 
		String securityHeader = String.format(securityHeaderXmlTemplate, timeNowString, expireTimeString, buildSoapMessageCredential(username,password));
		return securityHeader;
	}

	private String buildSoapMessageCredential(String username, String password) {
		String soapMessageCredential = String.format(soapMessageCredentialTemplate, username, password);
		return soapMessageCredential;
	}
}
