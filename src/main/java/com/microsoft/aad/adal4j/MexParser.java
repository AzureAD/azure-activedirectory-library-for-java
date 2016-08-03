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

import javax.net.ssl.SSLSocketFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.net.Proxy;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

class MexParser {

    private final static Logger log = LoggerFactory.getLogger(MexParser.class);

    private final static String TRANSPORT_BINDING_XPATH = "wsp:ExactlyOne/wsp:All/sp:TransportBinding";
    private final static String TRANSPORT_BINDING_2005_XPATH = "wsp:ExactlyOne/wsp:All/sp2005:TransportBinding";
    private final static String PORT_XPATH = "//wsdl:definitions/wsdl:service/wsdl:port";
    private final static String ADDRESS_XPATH = "wsa10:EndpointReference/wsa10:Address";
    private final static String SOAP_ACTION_XPATH = "wsdl:operation/soap12:operation/@soapAction";
    private final static String RST_SOAP_ACTION = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue";
    private final static String RST_SOAP_ACTION_2005 = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue";
    private final static String SOAP_TRANSPORT_XPATH = "soap12:binding/@transport";
    private final static String SOAP_HTTP_TRANSPORT_VALUE = "http://schemas.xmlsoap.org/soap/http";

    static BindingPolicy getWsTrustEndpointFromMexResponse(String mexResponse)
            throws Exception {
        DocumentBuilderFactory builderFactory = SafeDocumentBuilderFactory.createInstance();
        builderFactory.setNamespaceAware(true);
        DocumentBuilder builder = builderFactory.newDocumentBuilder();
        Document xmlDocument = builder.parse(new ByteArrayInputStream(
                mexResponse.getBytes(Charset.forName("UTF-8"))));

        XPath xPath = XPathFactory.newInstance().newXPath();
        NamespaceContextImpl nameSpace = new NamespaceContextImpl();
        xPath.setNamespaceContext(nameSpace);
        String xpathExpression = "//wsdl:definitions/wsp:Policy/wsp:ExactlyOne/wsp:All/"
                + "sp:SignedEncryptedSupportingTokens/wsp:Policy/sp:UsernameToken/"
                + "wsp:Policy/sp:WssUsernameToken10";
        Map<String, BindingPolicy> policies = selectUsernamePasswordPoliciesWithExpression(
                xmlDocument, xPath, xpathExpression);
        nameSpace.modifyNameSpace("sp",
                "http://schemas.xmlsoap.org/ws/2005/07/securitypolicy");
        xpathExpression = "//wsdl:definitions/wsp:Policy/wsp:ExactlyOne/wsp:All/"
                + "sp:SignedSupportingTokens/wsp:Policy/sp:UsernameToken/"
                + "wsp:Policy/sp:WssUsernameToken10";
        policies.putAll(selectUsernamePasswordPoliciesWithExpression(
                xmlDocument, xPath, xpathExpression));

        if (policies.isEmpty()) {
            log.debug("No matching policies");
            return null;
        }
        else {
            Map<String, BindingPolicy> bindings = getMatchingBindings(
                    xmlDocument, xPath, policies);

            if (bindings.isEmpty()) {
                log.debug("No matching bindings");
                return null;
            }
            else {
                getPortsForPolicyBindings(xmlDocument, xPath, bindings,
                        policies);
                return selectSingleMatchingPolicy(policies);
            }
        }
    }

    static BindingPolicy getWsTrustEndpointFromMexEndpoint(
            String metadataEndpoint, Proxy proxy,
            SSLSocketFactory sslSocketFactory) throws Exception {
        String mexResponse = HttpHelper.executeHttpGet(log, metadataEndpoint,
                proxy, sslSocketFactory);
        return getWsTrustEndpointFromMexResponse(mexResponse);
    }

    private static BindingPolicy selectSingleMatchingPolicy(
            Map<String, BindingPolicy> policies) {

        BindingPolicy wstrust13 = null, wstrust2005 = null;

        // Select wstrust13 first if wstrust13 available
        Iterator<Entry<String, BindingPolicy>> it = policies.entrySet()
                .iterator();
        while (it.hasNext()) {
            Map.Entry<String, BindingPolicy> pair = it.next();
            if (pair.getValue().getUrl() != null) {
                if (pair.getValue().getVersion() == WSTrustVersion.WSTRUST13) {
                    wstrust13 = pair.getValue();
                }
                else if (pair.getValue().getVersion() == WSTrustVersion.WSTRUST2005) {
                    wstrust2005 = pair.getValue();
                }
            }
        }

        if (wstrust13 == null && wstrust2005 == null) {
            log.warn("no policies found with the url");
            return null;
        }

        return wstrust13 != null ? wstrust13 : wstrust2005;
    }

    private static void getPortsForPolicyBindings(Document xmlDocument,
            XPath xPath, Map<String, BindingPolicy> bindings,
            Map<String, BindingPolicy> policies) throws Exception {

        NodeList portNodes = (NodeList) xPath.compile(PORT_XPATH).evaluate(
                xmlDocument, XPathConstants.NODESET);

        if (portNodes.getLength() == 0) {
            log.warn("no ports found");
        }
        else {
            for (int i = 0; i < portNodes.getLength(); i++) {
                Node portNode = portNodes.item(i);
                String bindingId = portNode.getAttributes()
                        .getNamedItem("binding").getNodeValue();
                String[] bindingIdParts = bindingId.split(":");
                bindingId = bindingIdParts[bindingIdParts.length - 1];
                BindingPolicy trustPolicy = bindings.get(bindingId);
                if (trustPolicy != null) {
                    BindingPolicy bindingPolicy = policies.get(trustPolicy
                            .getUrl());
                    if (bindingPolicy != null
                            && StringHelper.isBlank(bindingPolicy.getUrl())) {
                        bindingPolicy.setVersion(trustPolicy.getVersion());
                        NodeList addressNodes = (NodeList) xPath.compile(
                                ADDRESS_XPATH).evaluate(portNode,
                                XPathConstants.NODESET);
                        if (addressNodes.getLength() > 0) {
                            String address = addressNodes.item(0)
                                    .getTextContent();
                            if (address != null
                                    && address.toLowerCase().startsWith(
                                            "https://")) {
                                bindingPolicy.setUrl(address.trim());
                            }
                            else {
                                log.warn("skipping insecure endpoint: "
                                        + address);
                            }
                        }
                        else {
                            throw new Exception("no address nodes on port");
                        }
                    }
                }
            }
        }
    }

    private static Map<String, BindingPolicy> getMatchingBindings(
            Document xmlDocument, XPath xPath,
            Map<String, BindingPolicy> policies)
            throws XPathExpressionException {
        Map<String, BindingPolicy> bindings = new HashMap<String, BindingPolicy>();
        NodeList nodeList = (NodeList) xPath.compile(
                "//wsdl:definitions/wsdl:binding/wsp:PolicyReference")
                .evaluate(xmlDocument, XPathConstants.NODESET);
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            String uri = node.getAttributes().getNamedItem("URI")
                    .getNodeValue();
            if (policies.containsKey(uri)) {
                Node bindingNode = node.getParentNode();
                String bindingName = bindingNode.getAttributes()
                        .getNamedItem("name").getNodeValue();

                WSTrustVersion version = checkSoapActionAndTransport(xPath,
                        bindingNode);
                if (version != WSTrustVersion.UNDEFINED) {
                    BindingPolicy policy = new BindingPolicy("");
                    policy.setUrl(uri);
                    policy.setVersion(version);
                    bindings.put(bindingName, policy);
                }
            }
        }
        return bindings;
    }

    private static WSTrustVersion checkSoapActionAndTransport(XPath xPath,
            Node bindingNode) throws XPathExpressionException {
        NodeList soapTransportAttributes = null;
        String soapAction = null;
        String bindingName = bindingNode.getAttributes().getNamedItem("name")
                .getNodeValue();
        NodeList soapActionAttributes = (NodeList) xPath.compile(
                SOAP_ACTION_XPATH)
                .evaluate(bindingNode, XPathConstants.NODESET);
        if (soapActionAttributes.getLength() > 0) {
            soapAction = soapActionAttributes.item(0).getNodeValue();
            soapTransportAttributes = (NodeList) xPath.compile(
                    SOAP_TRANSPORT_XPATH).evaluate(bindingNode,
                    XPathConstants.NODESET);
            if (soapTransportAttributes != null
                    && soapTransportAttributes.getLength() > 0
                    && soapTransportAttributes.item(0).getNodeValue()
                            .equalsIgnoreCase(SOAP_HTTP_TRANSPORT_VALUE)) {

                if (soapAction.equalsIgnoreCase(RST_SOAP_ACTION)) {
                    log.debug("Found binding matching Action and Transport: "
                            + bindingName);
                    return WSTrustVersion.WSTRUST13;
                }
                else if (soapAction.equalsIgnoreCase(RST_SOAP_ACTION_2005)) {
                    log.debug("Binding node did not match soap Action or Transport: "
                            + bindingName);
                    return WSTrustVersion.WSTRUST2005;
                }
            }
        }

        return WSTrustVersion.UNDEFINED;
    }

    private static Map<String, BindingPolicy> selectUsernamePasswordPoliciesWithExpression(
            Document xmlDocument, XPath xPath, String xpathExpression)
            throws XPathExpressionException {

        Map<String, BindingPolicy> policies = new HashMap<String, BindingPolicy>();

        NodeList nodeList = (NodeList) xPath.compile(xpathExpression).evaluate(
                xmlDocument, XPathConstants.NODESET);
        for (int i = 0; i < nodeList.getLength(); i++) {

            // Nodes
            // sp:WssUsernameToken10
            // wsp:Policy
            // sp:UsernameToken
            // wsp:Policy
            // sp:SignedEncryptedSupportingTokens
            // wsp:All
            // wsp:ExactlyOne
            // wsp:Policy
            String policy = checkPolicy(xPath, nodeList.item(i).getParentNode()
                    .getParentNode().getParentNode().getParentNode()
                    .getParentNode().getParentNode().getParentNode());
            policies.put("#" + policy, new BindingPolicy("#" + policy));
        }
        return policies;
    }

    private static String checkPolicy(XPath xPath, Node node)
            throws XPathExpressionException {

        String policyId = null;
        Node id = node.getAttributes().getNamedItem("wsu:Id");
        NodeList transportBindingNodes = (NodeList) xPath.compile(
                TRANSPORT_BINDING_XPATH).evaluate(node, XPathConstants.NODESET);
        if (transportBindingNodes.getLength() == 0) {
            transportBindingNodes = (NodeList) xPath.compile(
                    TRANSPORT_BINDING_2005_XPATH).evaluate(node,
                    XPathConstants.NODESET);
        }

        if (transportBindingNodes.getLength() > 0 && id != null) {
            policyId = id.getNodeValue();
            log.debug("found matching policy id: " + policyId);
        }
        else {
            log.debug("potential policy did not match required transport binding: "
                    + id.getNodeValue());
        }
        return policyId;
    }
}
