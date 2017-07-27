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
package com.microsoft.aad.adal4jsample;

import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.microsoft.aad.adal4j.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class AadController {

    @Autowired
    ServletContext servletContext;

    private void setUserInfoAndTenant(ModelMap model, AuthenticationResult authenticationResult, HttpSession session){
                String tenant = session.getServletContext().getInitParameter("tenant");
                model.addAttribute("tenant", tenant);
                model.addAttribute("userInfo", authenticationResult.getUserInfo());
    }

    @RequestMapping("/secure/aad")
    public String getDirectoryObjects(ModelMap model, HttpServletRequest httpRequest) {
        HttpSession session = httpRequest.getSession();
        AuthenticationResult result = (AuthenticationResult) session.getAttribute(AuthHelper.PRINCIPAL_SESSION_NAME);
        if (result == null) {
            model.addAttribute("error", new Exception("AuthenticationResult not found in session."));
            return "/error";
        } else {
            setUserInfoAndTenant(model, result, session);

            String data;
            try {
                String tenant = session.getServletContext().getInitParameter("tenant");
                data = getUserNamesFromGraph(result.getAccessToken(), tenant);
                model.addAttribute("users", data);
            } catch (Exception e) {
                model.addAttribute("error", e);
                return "/error";
            }
        }
        return "secure/aad";
    }

    private String getUserNamesFromGraph(String accessToken, String tenant) throws Exception {
        URL url = new URL(String.format("https://graph.windows.net/%s/users?api-version=2013-04-05", tenant));

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        // Set the appropriate header fields in the request header.
        conn.setRequestProperty("api-version", "2013-04-05");
        conn.setRequestProperty("Authorization", accessToken);
        conn.setRequestProperty("Accept", "application/json;");
        String goodRespStr = HttpClientHelper.getResponseStringFromConn(conn, true);

        int responseCode = conn.getResponseCode();
        JSONObject response = HttpClientHelper.processGoodRespStr(responseCode, goodRespStr);
        JSONArray users;

        users = JSONHelper.fetchDirectoryObjectJSONArray(response);

        StringBuilder builder = new StringBuilder();
        User user;
        for (int i = 0; i < users.length(); i++) {
            JSONObject thisUserJSONObject = users.optJSONObject(i);
            user = new User();
            JSONHelper.convertJSONObjectToDirectoryObject(thisUserJSONObject, user);
            builder.append(user.getUserPrincipalName() + "<br/>");
        }
        return builder.toString();
    }

    @RequestMapping(value = "/secure/GetAtForMfaApiByRT", method = RequestMethod.GET)
    public String getATForMfaProtectedApiUsingRT(ModelMap model, HttpServletRequest httpRequest) throws MalformedURLException, InterruptedException {
        HttpSession session = httpRequest.getSession();
        AuthenticationResult result = (AuthenticationResult) session.getAttribute(AuthHelper.PRINCIPAL_SESSION_NAME);
        if (result == null) {
            model.addAttribute("error", new Exception("AuthenticationResult not found in session."));
            return "/error";
        } else {

            setUserInfoAndTenant(model, result, session);

            AuthenticationContext context;
            ExecutorService service = null;

            String clientId = servletContext.getInitParameter("client_id");
            String authority = servletContext.getInitParameter("authority");
            String tenant = servletContext.getInitParameter("tenant");
            String clientSecret = servletContext.getInitParameter("secret_key");
            String mfaProtectedApiIdUri = servletContext.getInitParameter("mfa_protected_api_id_uri");

            try{
                ClientCredential credential = new ClientCredential(clientId, clientSecret);
                service = Executors.newFixedThreadPool(1);

                context = new AuthenticationContext(authority + tenant + "/", true,
                        service);
                Future<AuthenticationResult> future = context.acquireTokenByRefreshToken(result.getRefreshToken(), credential,
                        mfaProtectedApiIdUri, null);

                result = future.get();

                model.addAttribute("acquiredToken", result.getAccessToken());

            } catch (ExecutionException e) {
                if(e.getCause() instanceof AdalClaimsChallengeException){

                    AdalClaimsChallengeException interReqExc = (AdalClaimsChallengeException)e.getCause();
                    AuthHelper.invalidateAuth(httpRequest);

                    return "redirect:/secure/aad" + "?claims=" + interReqExc.getClaims();
                }
            }
            finally {
                service.shutdown();
            }
        }
        return "secure/aad";
    }

    @RequestMapping(value = "/secure/GetAtForMfaApiUsingOboService", method = RequestMethod.GET)
    public String getATForMfaProtectedApiUsingOboService(ModelMap model, HttpServletRequest httpRequest) throws MalformedURLException, InterruptedException {
        HttpSession session = httpRequest.getSession();
        AuthenticationResult result = (AuthenticationResult) session.getAttribute(AuthHelper.PRINCIPAL_SESSION_NAME);
        if (result == null) {
            model.addAttribute("error", new Exception("AuthenticationResult not found in session."));
            return "/error";
        } else {

            setUserInfoAndTenant(model, result, session);

            AuthenticationContext context;
            ExecutorService service = null;

            // web app config
            String clientId = servletContext.getInitParameter("client_id");
            String authority = servletContext.getInitParameter("authority");
            String tenant = servletContext.getInitParameter("tenant");
            String clientSecret = servletContext.getInitParameter("secret_key");
            String oboApplicationIdUri = servletContext.getInitParameter("obo_application_id_uri");
            String mfaProtectedApiIdUri = servletContext.getInitParameter("mfa_protected_api_id_uri");

            try{
                ClientCredential credential = new ClientCredential(clientId, clientSecret);
                service = Executors.newFixedThreadPool(1);

                context = new AuthenticationContext(authority + tenant + "/", true,
                        service);

                // get AT for OBO service

                Future<AuthenticationResult> future = context.acquireTokenByRefreshToken(result.getRefreshToken(), credential,
                        oboApplicationIdUri, null);
                result = future.get();

                // get AT for Mfa protected Api using Obo client

                // obo config
                String oboClientId = servletContext.getInitParameter("obo_client_id");
                String oboClientSecret = servletContext.getInitParameter("obo_secret_key");

                ClientCredential oboCredential = new ClientCredential(oboClientId, oboClientSecret);

                future = context.acquireToken(mfaProtectedApiIdUri,
                        new ClientAssertion(result.getAccessToken()), oboCredential, null);

                result = future.get();

                model.addAttribute("acquiredToken", result.getAccessToken());
            } catch (ExecutionException e) {
                if(e.getCause() instanceof AdalClaimsChallengeException){

                    AdalClaimsChallengeException interReqExc = (AdalClaimsChallengeException)e.getCause();
                    AuthHelper.invalidateAuth(httpRequest);

                    return "redirect:/secure/aad" + "?claims=" + interReqExc.getClaims();
                }
            }
            finally {
                service.shutdown();
            }
        }
        return "secure/aad";
    }
}
