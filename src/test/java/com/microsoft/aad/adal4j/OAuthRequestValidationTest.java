package com.microsoft.aad.adal4j;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URLDecoder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import static org.powermock.api.support.membermodification.MemberMatcher.method;
import static org.powermock.api.support.membermodification.MemberModifier.replace;

import org.powermock.core.classloader.annotations.PrepareForTest;

import java.lang.reflect.InvocationHandler;

import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

@PrepareForTest(com.microsoft.aad.adal4j.AdalOAuthRequest.class)
public class OAuthRequestValidationTest extends PowerMockTestCase {

    private final static String AUTHORITY = "https://loginXXX.windows.net/path";

    private final static String CLIENT_ID = "ClientId";
    private final static String CLIENT_SECRET = "ClientPassword";

    private final static String RESOURCE = "https://SomeResource.azure.net";

    private final static String GRANT_TYPE_JWT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private final static String CLIENT_ASSERTION_TYPE_JWT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private final static String CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";

    private final static String OPEN_ID_SCOPE = "openid";

    private final static String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpva" +
            "G4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

    private static ExecutorService service = Executors.newFixedThreadPool(1);
    private AuthenticationContext context = new AuthenticationContext(AUTHORITY, false, service);
    private static String query;

    public OAuthRequestValidationTest() throws MalformedURLException {
    }

    @BeforeMethod
    public void init() {
        replace(method(com.microsoft.aad.adal4j.AdalOAuthRequest.class, "send")).
                with(new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                        OAuthRequestValidationTest.query = ((AdalOAuthRequest) proxy).getQuery();
                        throw new AuthenticationException("");
                    }
                });
    }

    @AfterClass
    public static void clean() {
        service.shutdown();
    }

    public static Map<String, String> splitQuery(String query) throws UnsupportedEncodingException {
        Map<String, String> query_pairs = new LinkedHashMap();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        return query_pairs;
    }

    private String getRSAjwt() throws NoSuchAlgorithmException, JOSEException {
        // RSA signatures require a public and private RSA key pair, the public key
        // must be made known to the JWS recipient in order to verify the signatures
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);

        KeyPair kp = keyGenerator.genKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(privateKey);

        // Prepare JWT with claims set
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.issuer("alice");
        builder.subject("alice");
        List<String> aud = new ArrayList<String>();
        aud.add("https://app-one.com");
        aud.add("https://app-two.com");
        builder.audience(aud);
        // Set expiration in 10 minutes
        builder.expirationTime(new Date(new Date().getTime() + 1000*60*10));
        builder.notBeforeTime(new Date());
        builder.issueTime(new Date());
        builder.jwtID(UUID.randomUUID().toString());

        JWTClaimsSet jwtClaims = builder.build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.RS256),
                jwtClaims);

        // Compute the RSA signature
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    @Test
    public void oAuthRequest_for_acquireTokenByUserAssertion() throws Exception {
        try {
            // Using UserAssertion as Authorization Grants
            Future<AuthenticationResult> future = context.acquireToken(RESOURCE, new UserAssertion(jwt),
                    new ClientCredential(CLIENT_ID,CLIENT_SECRET), null);
            future.get();
        }
        catch (ExecutionException ex){
            Assert.assertTrue(ex.getCause() instanceof AuthenticationException);
        }

        Map<String, String> queryParams = splitQuery(query);
        Assert.assertEquals(7, queryParams.size());

        // validate Authorization Grants query params
        Assert.assertEquals(GRANT_TYPE_JWT, queryParams.get("grant_type"));
        Assert.assertEquals(jwt, queryParams.get("assertion"));

        // validate Client Authentication query params
        Assert.assertEquals(CLIENT_ID, queryParams.get("client_id"));
        Assert.assertEquals(CLIENT_SECRET, queryParams.get("client_secret"));

        Assert.assertEquals(OPEN_ID_SCOPE, queryParams.get("scope"));

        Assert.assertEquals("on_behalf_of", queryParams.get("requested_token_use"));

        Assert.assertEquals(RESOURCE, queryParams.get("resource"));
    }

    @Test
    public void oAuthRequest_for_acquireTokenByClientAssertion() throws Exception {
        String rsaJwt = getRSAjwt();
        try {
            // Using ClientAssertion for Client Authentication and as the authorization grant
            Future<AuthenticationResult> future = context.acquireToken(RESOURCE, new ClientAssertion(rsaJwt), null);
            future.get();
        }
        catch (ExecutionException ex){
            Assert.assertTrue(ex.getCause() instanceof AuthenticationException);
        }

        Map<String, String> queryParams = splitQuery(query);

        Assert.assertEquals(5, queryParams.size());

        // validate Authorization Grants query params
        Assert.assertEquals(CLIENT_CREDENTIALS_GRANT_TYPE, queryParams.get("grant_type"));

        // validate Client Authentication query params
        Assert.assertEquals(rsaJwt, queryParams.get("client_assertion"));
        Assert.assertEquals(CLIENT_ASSERTION_TYPE_JWT, queryParams.get("client_assertion_type"));


        Assert.assertEquals(OPEN_ID_SCOPE, queryParams.get("scope"));

        Assert.assertEquals(RESOURCE, queryParams.get("resource"));
    }
}

