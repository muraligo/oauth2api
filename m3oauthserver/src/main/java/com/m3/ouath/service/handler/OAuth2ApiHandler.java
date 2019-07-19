package com.m3.ouath.service.handler;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.m3.common.oauth2.api.OAuth2.CODE_CHALLENGE_METHOD_S256;
import static com.m3.common.oauth2.api.OAuth2.MIN_CODE_VERIFIER_LENGTH;
import static com.m3.common.oauth2.api.OAuth2.MAX_CODE_VERIFIER_LENGTH;

import com.m3.common.oauth2.api.OAuth2;
import com.m3.oauth.common.AuthorizationService;
import com.m3.oauth.common.Client;
import com.m3.ouath.service.data.OAuth2DataProvider;

public class OAuth2ApiHandler implements AuthorizationService {
    // see Proof Key for Code Exchange (PKCE) RFC 7636
    private static final Pattern VALID_CODE_CHALLENGE_PATTERN = Pattern.compile("^[0-9a-zA-Z\\-\\.~_]+$");

    // Data Provider methods must be implemented in a thread safe manner
    private final OAuth2DataProvider _dataprovider;

    public OAuth2ApiHandler(OAuth2DataProvider dp) {
        _dataprovider = dp;
    }

    // All methods must be implemented in a thread safe manner
    @Override
    public AuthorizationResponse handleAuthorizationCode(String clientid, String redirecturi, String state, String challenge, String algorithm, String[] scopes) {
        Client cc = _dataprovider.getClientByIdOnly(clientid);
        if (cc == null) {
            throw new IllegalArgumentException("missing or invalid client id");
        }
        boolean insecureclient = false;
        // TODO figure out some config in the client to determine how secure it is
        // if client is not secure, it must use PKCE with SHA256
        if (insecureclient) {
            if (challenge == null || challenge.isBlank()) {
                throw new IllegalArgumentException("missing or invalid code challenge");
            }
            int cl = challenge.length();
            if (cl < MIN_CODE_VERIFIER_LENGTH || cl > MAX_CODE_VERIFIER_LENGTH) {
                throw new IllegalArgumentException("missing or invalid code challenge");
            }
            Matcher m = VALID_CODE_CHALLENGE_PATTERN.matcher(challenge);
            if (!m.matches()) {
                throw new IllegalArgumentException("missing or invalid code challenge");
            }
            if (algorithm == null || algorithm.isBlank() || CODE_CHALLENGE_METHOD_S256.equalsIgnoreCase(algorithm)) {
                // TODO throw an exception. what to throw so the correct error code gets returned?
                // something about unacceptable challenge algorithm
                throw new IllegalStateException("unacceptable challenge algorithm");
            }
            // TODO save the code challenge and algorithm with the client associated with code
            // Apparently you should not need to and you can verify easily if you do it right
            // see here https://www.oauth.com/oauth2-servers/authorization/the-authorization-response/
        }
        String code = ""; // TODO implement Util.getUUID();
        // TODO if client says redirect uri has to match, confirm it does
        // if not throw an IllegalStateException with something about unauthorized redirect_uri must match
        // see OAuth2CodeHandler notes
        if (redirecturi == null || redirecturi.isBlank()) {
            redirecturi = cc.redirecturl();
        }
        StringBuilder sb = new StringBuilder(redirecturi);
        sb.append("?code=");
        sb.append(code);
        if (state != null && !state.isBlank()) {
            sb.append("&state=");
            sb.append(state);
        }
        // TODO respond with the redirecturi to be placed in the "Location" header and status code of FOUND or is it 302
        return null;
    }

    // All methods must be implemented in a thread safe manner
    @Override
    public TokenResponse handlePassword(String clientid, String username, String pwmd5) {
		// TODO Auto-generated method stub
        return null;
    }

    // All methods must be implemented in a thread safe manner
    @Override
    public TokenResponse handleClientCredential(String clientid, String clientsecret) {
		// TODO Auto-generated method stub
        return null;
    }

    // All methods must be implemented in a thread safe manner
    @Override
    public TokenResponse handleToken(OAuth2.GrantType granttype, String clientid, String redirecturi, String clientsecret, String challenge, String code) {
        if (granttype == null) {
            throw new IllegalArgumentException("missing or invalid grant type");
        }
        Client cc = _dataprovider.getClientByIdOnly(clientid);
        if (cc == null) {
            throw new IllegalArgumentException("missing or invalid client id");
        }
        switch (granttype) {
        case AUTHORIZATION_CODE:
            if (code == null) {
                throw new IllegalArgumentException("missing or invalid authorization code");
            }
            boolean insecureclient = false;
            // TODO figure out some config in the client to determine how secure it is
            // if client is not secure, it must use PKCE with SHA256
            if (insecureclient) {
                if (challenge == null || challenge.isBlank()) {
                    throw new IllegalArgumentException("missing or invalid code verifier");
                }
                // TODO ensure secret matches; else throw an exception. what to throw so the correct error code gets returned?
                // this should result in an access_denied error
                // something about missing or invalid challenge
                // throw an IllegalStateException
                // see OAuth2CodeHandler notes
            } else {
                if (clientsecret == null || clientsecret.isBlank()) {
                    throw new IllegalArgumentException("missing or invalid client secret");
                }
                // TODO ensure secret matches; else throw an exception. what to throw so the correct error code gets returned?
                // this should result in an access_denied error
                // something about missing or invalid client secret
                // throw an IllegalStateException
                // see OAuth2CodeHandler notes
            }
            break;
        case CLIENT_CREDENTIALS:
            if (clientsecret == null || clientsecret.isBlank()) {
                throw new IllegalArgumentException("missing or invalid client secret");
            }
            // TODO ensure secret matches; else throw an exception. what to throw so the correct error code gets returned?
            // this should result in an access_denied error
            // something about missing or invalid client secret
            // throw an IllegalStateException
            // see OAuth2CodeHandler notes
            break;
        case PASSWORD:
            break;
        default:
            throw new IllegalArgumentException("missing or invalid grant type");
        }
        // TODO Generate a token, store it and return
        return null;
    }

}
