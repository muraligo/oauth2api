package com.m3.ouath.service.handler;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.m3.common.oauth2.api.OAuth2.CODE_CHALLENGE_METHOD_S256;
import static com.m3.common.oauth2.api.OAuth2.MIN_CODE_VERIFIER_LENGTH;
import static com.m3.common.oauth2.api.OAuth2.MAX_CODE_VERIFIER_LENGTH;

import com.m3.oauth.common.AuthorizationService;
import com.m3.oauth.common.Client;
import com.m3.ouath.service.data.OAuth2DataProvider;

public class OAuth2ApiHandler implements AuthorizationService {
    // see Proof Key for Code Exchange (PKCE) RFC 7636
    private static final Pattern VALID_CODE_CHALLENGE_PATTERN = Pattern.compile("^[0-9a-zA-Z\\-\\.~_]+$");

    private final OAuth2DataProvider _dataprovider;

    public OAuth2ApiHandler(OAuth2DataProvider dp) {
        _dataprovider = dp;
    }

    @Override
    public AuthorizationResponse handleAuthorizationCode(String clientid, String redirecturi, String state, String challenge, String algorithm, String[] scopes) {
        Client cc = _dataprovider.getClientByIdOnly(clientid);
        if (cc == null) {
            // TODO throw an exception. what to throw so the correct error code gets returned?
            // something about missing or invalid client id
        }
        boolean insecureclient = false;
        // TODO figure out some config in the client to determine how secure it is
        // if client is not secure, it must use PKCE with SHA256
        if (insecureclient) {
            if (challenge == null || challenge.isBlank()) {
                // TODO throw an exception. what to throw so the correct error code gets returned?
                // something about missing or invalid code challenge
            }
            if (algorithm == null || algorithm.isBlank() || CODE_CHALLENGE_METHOD_S256.equalsIgnoreCase(algorithm)) {
                // TODO throw an exception. what to throw so the correct error code gets returned?
                // something about unacceptable challenge algorithm
            }
            int cl = challenge.length();
            if (cl < MIN_CODE_VERIFIER_LENGTH || cl > MAX_CODE_VERIFIER_LENGTH) {
                // TODO throw an exception. what to throw so the correct error code gets returned?
                // something about missing or invalid code challenge
            }
            Matcher m = VALID_CODE_CHALLENGE_PATTERN.matcher(challenge);
            if (!m.matches()) {
                // TODO throw an exception. what to throw so the correct error code gets returned?
                // something about missing or invalid code challenge
            }
            // TODO save the code challenge and algorithm with the client associated with code
        }
        String code = ""; // TODO implement Util.getUUID();
        // TODO if client says redirect uri has to match, confirm it does
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

    @Override
    public TokenResponse handlePassword() {
		// TODO Auto-generated method stub
        return null;
    }

    @Override
    public TokenResponse handleClientCredential() {
		// TODO Auto-generated method stub
        return null;
    }

    @Override
    public TokenResponse handleToken() {
		// TODO Auto-generated method stub
        return null;
    }

}
