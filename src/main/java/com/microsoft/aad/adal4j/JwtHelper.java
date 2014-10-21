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

import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSHeader.Builder;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 *
 */
final class JwtHelper {
    /**
     * Builds JWT object.
     * 
     * @param credential
     * @return
     * @throws AuthenticationException
     */
    static ClientAssertion buildJwt(final AsymmetricKeyCredential credential,
            final String jwtAudience) throws AuthenticationException {
        if (credential == null) {
            throw new IllegalArgumentException("credential is null");
        }

        final JWTClaimsSet claimsSet = new AdalJWTClaimsSet();
        final List<String> audience = new ArrayList<String>();
        audience.add(jwtAudience);
        claimsSet.setAudience(audience);
        claimsSet.setIssuer(credential.getClientId());
        final long time = System.currentTimeMillis();
        claimsSet.setNotBeforeTime(new Date(time));
        claimsSet
                .setExpirationTime(new Date(
                        time
                                + AuthenticationConstants.AAD_JWT_TOKEN_LIFETIME_SECONDS
                                * 1000));
        claimsSet.setSubject(credential.getClientId());
        SignedJWT jwt = null;
        try {
            JWSHeader.Builder builder = new Builder(JWSAlgorithm.RS256);
            List<Base64> certs = new ArrayList<Base64>();
            certs.add(new Base64(credential.getPublicCertificate()));
            builder.x509CertChain(certs);
            builder.x509CertThumbprint(new Base64URL(credential
                  .getPublicCertificateHash()));
            jwt = new SignedJWT(builder.build(), claimsSet);
            final RSASSASigner signer = new RSASSASigner(
                    (RSAPrivateKey) credential.getKey());

            jwt.sign(signer);
        } catch (final Exception e) {
            throw new AuthenticationException(e);
        }

        return new ClientAssertion(jwt.serialize());
    }
}
