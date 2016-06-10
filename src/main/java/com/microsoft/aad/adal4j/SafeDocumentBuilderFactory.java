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

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

final class SafeDocumentBuilderFactory {

    public static DocumentBuilderFactory createInstance() throws ParserConfigurationException{

        final DocumentBuilderFactory builderFactory = DocumentBuilderFactory
                .newInstance();

        String feature = "http://apache.org/xml/features/disallow-doctype-decl";
        builderFactory.setFeature(feature, true);

        feature = "http://xml.org/sax/features/external-general-entities";
        builderFactory.setFeature(feature, false);

        feature = "http://xml.org/sax/features/external-parameter-entities";
        builderFactory.setFeature(feature, false);

        feature = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
        builderFactory.setFeature(feature, false);

        builderFactory.setXIncludeAware(false);
        builderFactory.setExpandEntityReferences(false);
   
        builderFactory.setNamespaceAware(true);
        return builderFactory;
    }
    
}
