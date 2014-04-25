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

import java.io.Reader;
import java.io.StringReader;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 *
 */
 class JsonHelper {
    /**
     * 
     * @param json
     * @param clazz
     * @return
     */
    static <T> T convertJsonToObject(final String json,
            final Class<T> clazz) {
        final Reader reader = new StringReader(json);
        final Gson gson = new GsonBuilder().create();
        return gson.fromJson(reader, clazz);
    }
}
