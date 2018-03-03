// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

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
            String msg = "No TokenType elements found in RSTR";
            log.warn(msg);
        }

        for (int i = 0; i < tokenTypeNodes.getLength(); i++) {
            if (!StringHelper.isBlank(responseValue.token)) {
                String msg = "Found more than one returned token.  Using the first.";
                log.warn(msg);

                break;
            }

            Node tokenTypeNode = tokenTypeNodes.item(i);
            responseValue.tokenType = tokenTypeNode.getTextContent();
            if (StringHelper.isBlank(responseValue.tokenType)) {
                String msg = "Could not find token type in RSTR token";
                log.warn(msg);
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
                String msg = "Unable to find RequestsSecurityToken element associated with TokenType element: "
                        + responseValue.tokenType;
                log.warn(msg);
                continue;
            }

            responseValue.token = innerXml(requestedTokenNodes.item(0));
            if (StringHelper.isBlank(responseValue.token)) {
                String msg = "Unable to find token associated with TokenType element: "
                        + responseValue.tokenType;
                log.warn(msg);

                continue;
            }

            String msg = "Found token of type: " + responseValue.tokenType;
            log.info(msg);
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
