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

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.Charset;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

class WSTrustResponse {

    private final static Logger log = LoggerFactory
            .getLogger(WSTrustResponse.class);

    public final static String SAML1_ASSERTION = "urn:oasis:names:tc:SAML:1.0:assertion";
    private String faultMessage;
    private boolean errorFound;
    private String errorCode;
    private String token;
    private String tokenType;

    private WSTrustResponse() {
    }

    String getFaultMessage() {
        return faultMessage;
    }

    boolean isErrorFound() {
        return errorFound;
    }

    String getErrorCode() {
        return errorCode;
    }

    String getToken() {
        return token;
    }

    String getTokenType() {
        return tokenType;
    }

    boolean isTokenSaml2() {
        return tokenType != null
                && !SAML1_ASSERTION.equalsIgnoreCase(tokenType);
    }

    static WSTrustResponse parse(String response, WSTrustVersion version)
            throws Exception {
        WSTrustResponse responseValue = new WSTrustResponse();
        DocumentBuilderFactory builderFactory = SafeDocumentBuilderFactory
                .createInstance();
        builderFactory.setNamespaceAware(true);
        DocumentBuilder builder = builderFactory.newDocumentBuilder();
        Document xmlDocument = builder.parse(new ByteArrayInputStream(response
                .getBytes(Charset.forName("UTF-8"))));
        XPath xPath = XPathFactory.newInstance().newXPath();
        NamespaceContextImpl namespace = new NamespaceContextImpl();
        xPath.setNamespaceContext(namespace);

        if (parseError(responseValue, xmlDocument, xPath)) {
            if (StringHelper.isBlank(responseValue.errorCode)) {
                responseValue.errorCode = "NONE";
            }
            if (StringHelper.isBlank(responseValue.faultMessage)) {
                responseValue.faultMessage = "NONE";
            }
            throw new Exception("Server returned error in RSTR - ErrorCode: "
                    + responseValue.errorCode + " : FaultMessage: "
                    + responseValue.faultMessage.trim());
        }
        else {
            parseToken(responseValue, xmlDocument, xPath, version);
        }

        return responseValue;
    }

    private static void parseToken(WSTrustResponse responseValue,
            Document xmlDocument, XPath xPath, WSTrustVersion version)
            throws Exception {

        NodeList tokenTypeNodes = (NodeList) xPath.compile(
                version.getResponseTokenTypePath()).evaluate(xmlDocument,
                XPathConstants.NODESET);
        if (tokenTypeNodes.getLength() == 0) {
            log.warn("No TokenType elements found in RSTR");
        }

        for (int i = 0; i < tokenTypeNodes.getLength(); i++) {
            if (!StringHelper.isBlank(responseValue.token)) {
                log.warn("Found more than one returned token.  Using the first.");
                break;
            }

            Node tokenTypeNode = tokenTypeNodes.item(i);
            responseValue.tokenType = tokenTypeNode.getTextContent();
            if (StringHelper.isBlank(responseValue.tokenType)) {
                log.warn("Could not find token type in RSTR token");
            }

            NodeList requestedTokenNodes = (NodeList) xPath.compile(
                    version.getResponseSecurityTokenPath()).evaluate(
                    tokenTypeNode.getParentNode(), XPathConstants.NODESET);
            if (requestedTokenNodes.getLength() > 1) {
                throw new Exception(
                        "Found too many RequestedSecurityToken nodes for token type: "
                                + responseValue.tokenType);
            }
            if (requestedTokenNodes.getLength() == 0) {
                log.warn("Unable to find RequestsSecurityToken element associated with TokenType element: "
                        + responseValue.tokenType);
                continue;
            }

            responseValue.token = innerXml(requestedTokenNodes.item(0));
            if (StringHelper.isBlank(responseValue.token)) {
                log.warn("Unable to find token associated with TokenType element: "
                        + responseValue.tokenType);
                continue;
            }
            log.info("Found token of type: " + responseValue.tokenType);
        }

        if (StringHelper.isBlank(responseValue.token)) {
            throw new Exception("Unable to find any tokens in RSTR");
        }
    }

    private static boolean parseError(WSTrustResponse responseValue,
            Document xmlDocument, XPath xPath) throws Exception {
        boolean errorFound = false;

        NodeList faultNodes = (NodeList) xPath.compile(
                "//s:Envelope/s:Body/s:Fault/s:Reason").evaluate(xmlDocument,
                XPathConstants.NODESET);

        if (faultNodes.getLength() > 0) {
            responseValue.faultMessage = faultNodes.item(0).getTextContent();
            if (!StringHelper.isBlank(responseValue.faultMessage)) {
                responseValue.errorFound = true;
            }
        }

        NodeList subcodeNodes = (NodeList) xPath.compile(
                "//s:Envelope/s:Body/s:Fault/s:Code/s:Subcode/s:Value")
                .evaluate(xmlDocument, XPathConstants.NODESET);
        if (subcodeNodes.getLength() > 1) {
            throw new Exception("Found too many fault code values:"
                    + subcodeNodes.getLength());
        }

        if (subcodeNodes.getLength() == 1) {
            responseValue.errorCode = subcodeNodes.item(0).getChildNodes()
                    .item(0).getTextContent();
            responseValue.errorCode = responseValue.errorCode.split(":")[1];
            errorFound = true;
        }

        return errorFound;
    }

    static String innerXml(Node node) {
        StringBuilder resultBuilder = new StringBuilder();
        NodeList children = node.getChildNodes();
        try {
            Transformer transformer = TransformerFactory.newInstance()
                    .newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION,
                    "yes");
            // transformer.setOutputProperty(OutputKeys.INDENT, "yes");

            StringWriter sw = new StringWriter();
            StreamResult streamResult = new StreamResult(sw);

            for (int index = 0; index < children.getLength(); index++) {
                Node child = children.item(index);

                // Print the DOM node
                DOMSource source = new DOMSource(child);
                transformer.transform(source, streamResult);
                // Append child to end result
                resultBuilder.append(sw.toString());
            }

        }
        catch (Exception ex) {
            ex.printStackTrace();
        }

        return resultBuilder.toString().trim();
    }

}
