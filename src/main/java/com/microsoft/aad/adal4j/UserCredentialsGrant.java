package com.microsoft.aad.adal4j;

import java.util.LinkedHashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;

/**
* User credentials grant. Used in access token requests with a user's username and password. This class is immutable.
*
* <p>Related specifications:
*
* <ul>
*     <li>OAuth 2.0 (RFC 6749), section 4.3.2.
* </ul>
*
*/
@Immutable
public class UserCredentialsGrant extends AuthorizationGrant {

    public static final GrantType GRANT_TYPE = GrantType.PASSWORD;
    
    private final Scope scope;
    
    public UserCredentialsGrant(final Scope scope) {
        super(GRANT_TYPE);
        this.scope = scope;
    }

    public Scope getScope() {
        return scope;
    }
    
    @Override
    public Map<String, String> toParameters() {
        Map<String,String> params = new LinkedHashMap<String,String>();

        params.put("grant_type", GRANT_TYPE.getValue());
        if (scope != null)
            params.put("scope", scope.toString());
            return params;
    }

}
