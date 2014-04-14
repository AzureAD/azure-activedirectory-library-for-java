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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.microsoft.adal4j.AuthenticationResult;
import com.microsoft.windowsazure.activedirectory.sdk.graph.exceptions.SdkException;
import com.microsoft.windowsazure.activedirectory.sdk.graph.models.User;
import com.microsoft.windowsazure.activedirectory.sdk.graph.models.UserList;
import com.microsoft.windowsazure.activedirectory.sdk.graph.services.UserService;

@Controller
@RequestMapping("/secure/aad")
public class AadController {

    @RequestMapping(method = RequestMethod.GET)
    public String getDirectoryObjects(ModelMap model,
            HttpServletRequest httpRequest) {
        HttpSession session = httpRequest.getSession();
        AuthenticationResult result = (AuthenticationResult) session
                .getAttribute(AuthHelper.PRINCIPAL_SESSION_NAME);
        if (result == null) {
            model.addAttribute("error", new Exception(
                    "AuthenticationResult not found in session."));
            return "/error";
        } else {
            UserService service = new UserService(result.getAccessToken(),
                    session.getServletContext().getInitParameter("tenant"));
            UserList list = new UserList();
            try {
                list = service.queryAllUsers(null);
            } catch (SdkException e) {
                httpRequest.setAttribute("error", e.getMessage());
                return "/error";
            }
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < list.getListSize(); i++) {
                User user = list.getSingleDirectoryObject(i);
                builder.append(user.getUserPrincipalName() + "<br/>");
            }
            model.addAttribute("users", builder.toString());
        }
        return "/secure/aad";
    }
}
