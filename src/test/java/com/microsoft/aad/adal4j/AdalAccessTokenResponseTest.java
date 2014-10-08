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

import java.text.ParseException;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

@Test(groups = { "checkin" })
public class AdalAccessTokenResponseTest extends AbstractAdalTests {

    private final String idToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5HVEZ2ZEstZnl0aEV1THdqcHdBSk9NOW4tQSJ9."
            + "eyJhdWQiOiIyMTZlZjgxZC1mM2IyLTQ3ZDQtYWQyMS1hNGRmNDliNTZkZWUiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5l"
            + "dC9kM2VhYjEzMi1iM2Y3LTRkNzktOTM5Yy0zMDIyN2FlYjhjMjYvIiwiaWF0IjoxMzkzNDk2MDM3LCJuYmYiOjEzOTM0OTYwMzcsI"
            + "mV4cCI6MTM5MzQ5OTkzNywidmVyIjoiMS4wIiwidGlkIjoiZDNlYWIxMzItYjNmNy00ZDc5LTkzOWMtMzAyMjdhZWI4YzI2Iiwib2l"
            + "kIjoiMzZiNjE4MTMtM2EyYi00NTA4LWFlOGQtZmM3NTQyMDE3NTlhIiwidXBuIjoibWVAa2FuaXNoa3BhbndhcmhvdG1haWwub25ta"
            + "WNyb3NvZnQuY29tIiwidW5pcXVlX25hbWUiOiJtZUBrYW5pc2hrcGFud2FyaG90bWFpbC5vbm1pY3Jvc29mdC5jb20iLCJzdWIiOiJ"
            + "mZU40RU4wTW1vQ3ZubFZoRk1KeWozMzRSd0NaTGxrdTFfMVQ1VlNSN0xrIiwiZmFtaWx5X25hbWUiOiJQYW53YXIiLCJnaXZlbl9uYW"
            + "1lIjoiS2FuaXNoayIsIm5vbmNlIjoiYTM1OWY0MGItNDJhOC00YTRjLTk2YWMtMTE0MjRhZDk2N2U5IiwiY19oYXNoIjoib05kOXE1e"
            + "m1fWTZQaUNpYTg1MDZUQSJ9.iyGfoL0aKai-rZVGFwaCYm73h2Dk93M80CRAOoIwlxAKfGrQ2YDbvAPIvlQUrNQacqzenmkJvVEMqXT"
            + "OYO5teyweUkxruod_iMgmhC6RZZZ603vMoqItUVu8c-4Y3KIEweRi17BYjdR2_tEowPlcEteRY52nwCmiNJRQnkqnQ2aZP89Jzhb9qw"
            + "_G3CeYsOmV4f7jUp7anDT9hae7eGuvdUAf4LTDD6hFTBJP8MsyuMD6DkgBytlSxaXXJBKBJ5r5XPHdtStCTNF7edktlSufA2owTWVGw"
            + "gWpKmnue_2Mgl3jBozTSJJ34r-R6lnWWeN6lqZ2Svw7saI5pmPtC8OZbw";

    @Test
    public void testConstructor() throws ParseException {
        final AdalAccessTokenResponse response = new AdalAccessTokenResponse(
                new BearerAccessToken("access_token"), new RefreshToken(
                        "refresh_token"), idToken);
        Assert.assertNotNull(response);
        final JWT jwt = response.getIDToken();
        Assert.assertTrue(jwt.getJWTClaimsSet().getAllClaims().size() >= 0);
    }

    @Test
    public void testParseJsonObject()
            throws com.nimbusds.oauth2.sdk.ParseException {
        final AdalAccessTokenResponse response = AdalAccessTokenResponse
                .parseJsonObject(JSONObjectUtils
                        .parseJSONObject(TestConfiguration.HTTP_RESPONSE_FROM_AUTH_CODE));
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getIDToken());
        Assert.assertFalse(StringHelper.isBlank(response.getIDTokenString()));
        Assert.assertFalse(StringHelper.isBlank(response.getResource()));
    }
}
