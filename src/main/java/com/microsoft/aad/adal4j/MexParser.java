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

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

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
    private final static String SOAP_TRANSPORT_XPATH = "soap12:binding/@transport";
    private final static String SOAP_HTTP_TRANSPORT_VALUE = "http://schemas.xmlsoap.org/soap/http";

    static String getWsTrustEndpointFromMexResponse(String mexResponse)
            throws Exception {
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory
                .newInstance();
        builderFactory.setNamespaceAware(true);
        DocumentBuilder builder = builderFactory.newDocumentBuilder();
        Document xmlDocument = builder.parse(new ByteArrayInputStream(
                mexResponse.getBytes(Charset.forName("UTF-8"))));

        XPath xPath = XPathFactory.newInstance().newXPath();
        xPath.setNamespaceContext(new NamespaceContextImpl());
        Map<String, BindingPolicy> policies = selectUsernamePasswordPolicies(
                xmlDocument, xPath);

        if (policies.isEmpty()) {
            log.debug("No matching policies");
            return null;
        } else {
            Map<String, String> bindings = getMatchingBindings(xmlDocument,
                    xPath, policies);

            if (bindings.isEmpty()) {
                log.debug("No matching bindings");
                return null;
            } else {
                getPortsForPolicyBindings(xmlDocument, xPath, bindings,
                        policies);
                return selectSingleMatchingPolicy(policies).trim();
            }
        }
    }

    static String getWsTrustEndpointFromMexEndpoint(String metadataEndpoint)
            throws Exception {
        String mexResponse = HttpHelper.executeHttpGet(log, metadataEndpoint);
        return getWsTrustEndpointFromMexResponse(mexResponse);
    }

    private static String selectSingleMatchingPolicy(
            Map<String, BindingPolicy> policies) {
        for (String key : policies.keySet()) {
            if (policies.get(key).getUrl() == null) {
                policies.remove(key);
            }
        }

        if (policies.size() == 0) {
            log.warn("no policies found with an url");
            return null;
        }
        return policies.values().iterator().next().getUrl();
    }

    private static Map<String, String> getPortsForPolicyBindings(
            Document xmlDocument, XPath xPath, Map<String, String> bindings,
            Map<String, BindingPolicy> policies) throws Exception {

        NodeList portNodes = (NodeList) xPath.compile(PORT_XPATH).evaluate(
                xmlDocument, XPathConstants.NODESET);

        if (portNodes.getLength() == 0) {
            log.warn("no ports found");
        } else {
            for (int i = 0; i < portNodes.getLength(); i++) {
                Node portNode = portNodes.item(i);
                String bindingId = portNode.getAttributes()
                        .getNamedItem("binding").getNodeValue();
                String[] bindingIdParts = bindingId.split(":");
                bindingId = bindingIdParts[bindingIdParts.length - 1];
                BindingPolicy bindingPolicy = policies.get(bindings
                        .get(bindingId));
                if (bindingPolicy != null
                        && StringHelper.isBlank(bindingPolicy.getUrl())) {
                    NodeList addressNodes = (NodeList) xPath.compile(
                            ADDRESS_XPATH).evaluate(portNode,
                            XPathConstants.NODESET);
                    if (addressNodes.getLength() > 0) {
                        String address = addressNodes.item(0).getTextContent();
                        if (address != null
                                && address.toLowerCase().startsWith("https://")) {
                            bindingPolicy.setUrl(address);
                        } else {
                            log.warn("skipping insecure endpoint: " + address);
                        }
                    } else {
                        throw new Exception("no address nodes on port");
                    }
                }
            }
        }

        return null;
    }

    private static Map<String, String> getMatchingBindings(
            Document xmlDocument, XPath xPath,
            Map<String, BindingPolicy> policies)
            throws XPathExpressionException {
        Map<String, String> bindings = new HashMap<String, String>();
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
                if (checkSoapActionAndTransport(xPath, bindingNode)) {
                    bindings.put(bindingName, uri);
                }
            }
        }
        return bindings;
    }

    private static boolean checkSoapActionAndTransport(XPath xPath,
            Node bindingNode) throws XPathExpressionException {
        NodeList soapTransportAttributes = null;
        String soapAction = null;
        String soapTransport = null;
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
        }

        if (soapTransportAttributes != null
                && soapTransportAttributes.getLength() > 0) {
            soapTransport = soapTransportAttributes.item(0).getNodeValue();
        }

        boolean found = soapAction.equalsIgnoreCase(RST_SOAP_ACTION)
                && soapTransport.equalsIgnoreCase(SOAP_HTTP_TRANSPORT_VALUE);
        if (found) {
            log.debug("Found binding matching Action and Transport: "
                    + bindingName);
        } else {
            log.debug("Binding node did not match soap Action or Transport: "
                    + bindingName);
        }

        return found;
    }

    private static Map<String, BindingPolicy> selectUsernamePasswordPolicies(
            Document xmlDocument, XPath xPath) throws XPathExpressionException {
        String xpathExpression = "//wsdl:definitions/wsp:Policy/wsp:ExactlyOne/wsp:All/"
                + "sp:SignedEncryptedSupportingTokens/wsp:Policy/sp:UsernameToken/"
                + "wsp:Policy/sp:WssUsernameToken10";
        Map<String, BindingPolicy> policies = new HashMap<String, BindingPolicy>();

        NodeList nodeList = (NodeList) xPath.compile(xpathExpression).evaluate(
                xmlDocument, XPathConstants.NODESET);
        for (int i = 0; i < nodeList.getLength(); i++) {
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
        } else {
            log.debug("potential policy did not match required transport binding: "
                    + id.getNodeValue());
        }
        return policyId;
    }
}
