package com.m3.oauth.common;

import com.m3.common.oauth2.api.OAuth2;

public interface AuthorizationService {
    AuthorizationResponse handleAuthorizationCode(String clientid, String redirecturi, String state, String challenge, String algorithm, String[] scopes);
    TokenResponse handlePassword(String clientid, String username, String pwmd5);
    TokenResponse handleClientCredential(String clientid, String clientsecret);
    TokenResponse handleToken(OAuth2.GrantType granttype, String clientid, String redirecturi, String clientsecret, String challenge, String code);
    // TODO for the above provide parameters

    public class AuthorizationResponse extends BaseResponse  {

        protected AuthorizationResponse(SuccessResponseType typ) {
            super(typ);
        }

    	// TODO implement
    }

    public class TokenResponse extends BaseResponse {

        protected TokenResponse(SuccessResponseType typ) {
            super(typ);
        }

        // TODO Implement
    }
}
