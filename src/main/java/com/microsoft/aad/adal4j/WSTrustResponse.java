package com.microsoft.aad.adal4j;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.util.Iterator;

import javax.xml.namespace.QName;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPBodyElement;
import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class WSTrustResponse {

	public static WSTrustResponse processResponse(
			HttpURLConnection httpUrlConnection) {
		InputStream inputStream = null;
		try {
			inputStream = (InputStream) httpUrlConnection.getContent();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		WSTrustResponse wsTrustResponse = getTokenFromSoapStream(inputStream);
		
		return wsTrustResponse;
	}
	
	private static WSTrustResponse getTokenFromSoapStream(InputStream inputStream) {
		MessageFactory messageFactory = null;
		try {
			messageFactory = MessageFactory.newInstance(SOAPConstants.SOAP_1_2_PROTOCOL);
		} catch (SOAPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		SOAPMessage soapMessage = null;
		try {
			soapMessage = messageFactory.createMessage(null, inputStream);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SOAPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		SOAPBody soapBody = null;
		try {
			soapBody = soapMessage.getSOAPBody();
		} catch (SOAPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String namespaceURI = "http://docs.oasis-open.org/us-sx/ws-trust/200512";
		String localPart = "RequestSecurityTokenResponseCollection";
		String prefix = "trust";
		String tokenType = "";
		String token = "";
		QName qname = new QName(namespaceURI, localPart, prefix);
		SOAPBodyElement requestSecurityTokenResponseCollection = (SOAPBodyElement) soapBody.getChildElements().next();
		
		SOAPBodyElement requestSecurityTokenResponse = (SOAPBodyElement)requestSecurityTokenResponseCollection.getChildElements().next();
		Iterator<?> childElements = requestSecurityTokenResponse.getChildElements();
		while (childElements.hasNext())
		{
			SOAPBodyElement bodyElement = (SOAPBodyElement) childElements.next();
			String elementValue = bodyElement.getValue();
			if (bodyElement.getLocalName().equals("TokenType"))
			{
				tokenType = bodyElement.getValue();
			}
			
			if (bodyElement.getLocalName().equals("RequestedSecurityToken"))
			{
				token = getNodeInnerXml(bodyElement);
			}
			System.out.println("The value is : " + elementValue );
		}
		System.out.println("The token value is : " + token);
		System.out.println("The token type is :" + tokenType);
		
		WSTrustResponse wsTrustResponse = new WSTrustResponse();
		wsTrustResponse.setTokenType(tokenType);
		wsTrustResponse.setToken(token);
			
		return wsTrustResponse;
	}
	
	public void setToken(String token) {
		this.token = token;
	}

	private void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}

	private static String getNodeInnerXml(Node node)
	{
		NodeList nodeList = node.getChildNodes();
		String result = "";
		for (int i =0 ; i<nodeList.getLength(); i++)
		{
			Node nodeItem = nodeList.item(i);
			String nodeItemString = getNodeXml(nodeItem);
			result = result + nodeItemString;
		}
		return result; 
	}
	
	private static String getNodeXml(Node node) {
		DOMSource domSource = new DOMSource(node);
		StringWriter stringWriter = new StringWriter();
		try {
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			transformer.transform(domSource, new StreamResult(stringWriter));
		} catch (TransformerException e) {
			throw new RuntimeException(e);
		}
		
		return stringWriter.toString();
	}

	
	private static String getStringFromInputStream(InputStream is) {
		 
		BufferedReader br = null;
		StringBuilder sb = new StringBuilder();
 
		String line;
		try {
 
			br = new BufferedReader(new InputStreamReader(is));
			while ((line = br.readLine()) != null) {
				sb.append(line);
			}
 
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
 
		return sb.toString();
	}

	private String errorCode;
	private String faultMessage;
	private String tokenType;
	private String token;
	
	public String getErrorCode() {
		return this.errorCode;
	}
	
	public String getFaultMessage(){
		return this.faultMessage;
	}
	
	public String getTokenType() {
		return this.tokenType;
	}
	
	public String getToken() {
		return this.token;
	}
	

}
