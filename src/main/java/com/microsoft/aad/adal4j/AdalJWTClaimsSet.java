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

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWTClaimsSet;

/**
 *
 */
class AdalJWTClaimsSet extends JWTClaimsSet {

    static final String AUDIENCE_CLAIM = "aud";

    @Override
    public JSONObject toJSONObject() {
        final JSONObject jo = super.toJSONObject();

        // Service does not support arrays. If more than 1 value is passed for
        // audience, first one is selected.
        if (jo.get(AUDIENCE_CLAIM) != null) {
            if (!(jo.get(AUDIENCE_CLAIM) instanceof String)) {
                final JSONArray arr = (JSONArray) jo.get(AUDIENCE_CLAIM);
                if (!arr.isEmpty()) {
                    jo.put(AUDIENCE_CLAIM, arr.get(0));
                } else {
                    jo.remove(AUDIENCE_CLAIM);
                }
            }
        }
        return jo;
    }
}
