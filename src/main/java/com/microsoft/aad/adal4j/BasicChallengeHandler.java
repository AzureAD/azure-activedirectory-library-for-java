/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 */

package com.microsoft.aad.adal4j;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * An implementation of the ChallengeHandler that can satisfy a Basic
 * authentication challenge.
 */
public class BasicChallengeHandler implements ChallengeHandler {
    private AtomicInteger nonceCounter = new AtomicInteger(0);
    private String username;
    private String password;

    /**
     * Creates a BasicChallengeHandler.
     * @param username the username to authenticate
     * @param password the password to authenticate
     */
    public BasicChallengeHandler(String username, String password) {
        this.username = username;
        this.password = password;
    }

    @Override
    public String handle(String httpMethod, String uri, List<String> wwwAuthenticate) {
        String token = username + ":" + password;
        return "Basic " + Base64.encodeBase64String(token.getBytes());
    }
}
