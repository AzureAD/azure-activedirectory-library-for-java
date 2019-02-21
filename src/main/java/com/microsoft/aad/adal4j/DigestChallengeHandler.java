/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 */

package com.microsoft.aad.adal4j;

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
 * An implementation of the ChallengeHandler that can satisfy a Digest
 * authentication challenge.
 */
public class DigestChallengeHandler implements ChallengeHandler {
    private AtomicInteger nonceCounter = new AtomicInteger(0);
    private String username;
    private String password;

    /**
     * Creates a DigestChallengeHandler.
     * @param username the username to authenticate
     * @param password the password to authenticate
     */
    public DigestChallengeHandler(String username, String password) {
        this.username = username;
        this.password = password;
    }

    @Override
    public String handle(String httpMethod, String uri, List<String> wwwAuthenticate) {
        Map<String, String> challenge = null;
        for (String w : wwwAuthenticate) {
            if (w.toLowerCase().startsWith("digest")) {
                challenge = parseChallengeHeader(w);
                break;
            }
        }
        if (challenge == null) {
            throw new UnsupportedOperationException("Cannot find WWW-Authenticate / Proxy-Authenticate header with Digest authentication.");
        }

        String realm = challenge.get("realm");
        String nonce = challenge.get("nonce");
        String qop = challenge.get("qop");

        return handleIntern(realm, nonce, qop, httpMethod, uri);
    }

    private static Map<String, String> parseChallengeHeader(String header) {
        String maps = header.replaceFirst("[Dd]igest\\ ", "");
        String[] parts = maps.split(",");
        Map<String, String> fields = new HashMap<>();
        for (String part : parts) {
            String[] keyValuePair = part.trim().split("=", 2);
            assert keyValuePair.length == 2;
            fields.put(keyValuePair[0], keyValuePair[1].replaceAll("^\"", "").replaceAll("\"$", ""));
        }
        return fields;
    }

    private String handleIntern(String realm, String nonce, String qop, String httpMethod, String uri) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("md5");
            SecureRandom secureRandom = new SecureRandom();
            String a1 = Hex.encodeHexString(md5.digest(String.format("%s:%s:%s", username, realm, password).getBytes(StandardCharsets.UTF_8)));
            String a2 = Hex.encodeHexString(md5.digest(String.format("%s:%s", httpMethod.toUpperCase(), uri).getBytes(StandardCharsets.UTF_8)));

            byte[] cnonceBytes = new byte[16];
            secureRandom.nextBytes(cnonceBytes);
            String cnonce = Hex.encodeHexString(cnonceBytes);
            String response;
            if (qop == null || qop.isEmpty()) {
                response = Hex.encodeHexString(md5.digest(String.format("%s:%s:%s", a1, nonce, a2).getBytes(StandardCharsets.UTF_8)));
                return String.format("Digest username=\"%s\",realm=\"%s\",nonce=\"%s\",uri=\"%s\",cnonce=\"%s\",response=\"%s\"",
                        username, realm, nonce, uri, cnonce, response);
            } else {
                int nc = nonceCounter.incrementAndGet();
                response = Hex.encodeHexString(md5.digest(String.format("%s:%s:%08X:%s:%s:%s", a1, nonce, nc, cnonce, qop, a2).getBytes(StandardCharsets.UTF_8)));
                return String.format("Digest username=\"%s\",realm=\"%s\",nonce=\"%s\",uri=\"%s\",cnonce=\"%s\",nc=%08X,response=\"%s\",qop=\"%s\"",
                        username, realm, nonce, uri, cnonce, nc, response, qop);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
