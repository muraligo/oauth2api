package com.m3.oauth.common;

public interface AuthorizationService {
    AuthorizationResponse handleAuthorizationCode(String clientid, String redirecturi, String state, String challenge, String algorithm, String[] scopes);
    TokenResponse handlePassword();
    TokenResponse handleClientCredential();
    TokenResponse handleToken();
    // TODO for the above provide parameters

    public class AuthorizationResponse {
    	// TODO implement
    }

    public class TokenResponse {
        // TODO Implement
    }
}
