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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Enumeration;

import org.apache.commons.codec.binary.Base64;

/**
 * Credential type containing X509 public certificate and RSA private key.
 */
public final class AsymmetricKeyCredential {
    public final static int MIN_KEYSIZE_IN_BITS = 2048;
    private final String clientId;
    private final PrivateKey key;
    private final X509Certificate publicCertificate;

    /**
     * Constructor to create credential with client id, private key and public
     * certificate.
     * 
     * @param clientId
     *            Identifier of the client requesting the token.
     * @param key
     *            RSA private key to sign the assertion.
     * @param publicCertificate
     *            Public certificate used for thumb print.
     */
    private AsymmetricKeyCredential(final String clientId,
            final PrivateKey key, final X509Certificate publicCertificate) {
        if (StringHelper.isBlank(clientId)) {
            throw new IllegalArgumentException("clientId is null or empty");
        }

        if (key == null) {
            throw new NullPointerException("PrivateKey");
        }

        this.clientId = clientId;
        this.key = key;

        if (((RSAPrivateKey) key).getModulus().bitLength() < MIN_KEYSIZE_IN_BITS) {
            throw new IllegalArgumentException(
                    "certificate key size must be at least "
                            + MIN_KEYSIZE_IN_BITS);
        }
        this.publicCertificate = publicCertificate;
    }

    /**
     * Gets the identifier of the client requesting the token.
     * 
     * @return string value
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Base64 encoded hash of the the public certificate.
     * 
     * @return base64 endoded string
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     */
    public String getPublicCertificateHash()
            throws CertificateEncodingException, NoSuchAlgorithmException {
        return Base64.encodeBase64String(AsymmetricKeyCredential
                .getHash(this.publicCertificate.getEncoded()));
    }

    /**
     * Base64 encoded public certificate.
     * 
     * @return base64 endoded string
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     */
    public String getPublicCertificate()
            throws CertificateEncodingException, NoSuchAlgorithmException {
        return Base64.encodeBase64String(this.publicCertificate.getEncoded());
    }
    
    /**
     * Returns private key of the credential.
     * 
     * @return private key.
     */
    public Key getKey() {
        return key;
    }

    /**
     * Static method to create KeyCredential instance.
     * 
     * @param clientId
     *            Identifier of the client requesting the token.
     * @param pkcs12Certificate
     *            PKCS12 certificate stream containing public and private key.
     *            Caller is responsible to handling the inputstream.
     * @param password
     *            certificate password
     * @return KeyCredential instance
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws UnrecoverableKeyException
     */
    public static AsymmetricKeyCredential create(final String clientId,
            final InputStream pkcs12Certificate, final String password)
            throws KeyStoreException, NoSuchProviderException,
            NoSuchAlgorithmException, CertificateException,
            FileNotFoundException, IOException, UnrecoverableKeyException {
        final KeyStore keystore = KeyStore.getInstance("PKCS12", "SunJSSE");
        keystore.load(pkcs12Certificate, password.toCharArray());
        final Enumeration<String> aliases = keystore.aliases();
        final String alias = aliases.nextElement();
        final PrivateKey key = (PrivateKey) keystore.getKey(alias,
                password.toCharArray());
        final X509Certificate publicCertificate = (X509Certificate) keystore
                .getCertificate(alias);
        return create(clientId, key, publicCertificate);
    }

    /**
     * Static method to create KeyCredential instance.
     * 
     * @param clientId
     *            Identifier of the client requesting the token.
     * @param key
     *            RSA private key to sign the assertion.
     * @param publicCertificate
     *            Public certificate used for thumb print.
     * @return KeyCredential instance
     */
    public static AsymmetricKeyCredential create(final String clientId,
            final PrivateKey key, final X509Certificate publicCertificate) {
        return new AsymmetricKeyCredential(clientId, key, publicCertificate);
    }

    private static byte[] getHash(final byte[] inputBytes)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        final MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(inputBytes);
        return md.digest();

    }

}
