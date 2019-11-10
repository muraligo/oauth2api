package com.m3.ouath.service.handler;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.m3.common.oauth2.api.OAuth2.CODE_CHALLENGE_METHOD_S256;
import static com.m3.common.oauth2.api.OAuth2.MIN_CODE_VERIFIER_LENGTH;
import static com.m3.common.oauth2.api.OAuth2.MAX_CODE_VERIFIER_LENGTH;

import com.m3.common.oauth2.api.OAuth2;
import com.m3.oauth.common.AuthorizationService;
import com.m3.oauth.common.Client;
import com.m3.oauth.common.BaseResponse.M3OAuthError;
import com.m3.oauth.service.data.OAuth2DataProvider;
import com.m3.ouath.service.data.OAuth2AccessToken;

public class OAuth2ApiHandler implements AuthorizationService {
    // see Proof Key for Code Exchange (PKCE) RFC 7636
    private static final Pattern VALID_CODE_CHALLENGE_PATTERN = Pattern.compile("^[0-9a-zA-Z\\-\\.~_]+$");
    // TODO should ideally take from config
    private static final int EXPIRY_MINUTES = 15;

    // Data Provider methods must be implemented in a thread safe manner
    private final OAuth2DataProvider _dataprovider;

    private final String _sshkeyfile;

    public OAuth2ApiHandler(OAuth2DataProvider dp, String sshkeyfile) {
        _dataprovider = dp;
        _sshkeyfile = sshkeyfile;
    }

    // All methods must be implemented in a thread safe manner
    // TODO replace all formErrorResponse instances with the appropriate OAuth2 standard error response
    // see https://www.oauth.com/oauth2-servers/authorization/the-authorization-response/
    // it should be in a JSON or XML body based on the Accept-Type
    // this should be an error response code corresponding to the following
    // if IllegalArgumentException, message should start with "missing or invalid "
    // restate the message as "missing or invalid request parameters" and put in the 
    // error_description. In the error field use exactly "invalid_request". 
    // Response is BAD_REQUEST
    // if IllegalStateException, if it starts with "unacceptable", response 
    // should be a 302 with error exactly "unsupported_response_type" and description 
    // of the message in entirity
    // if IllegalStateException, if it starts with "unauthorized", response is 
    // 403 with error exactly "access_denied" and message as "user or server denied access"
    @Override
    public AuthorizationResponse handleAuthorizationCode(String clientid, String redirecturi, String state, String challenge, String algorithm, String[] scopes) {
        Client cc = _dataprovider.getClientByIdOnly(clientid);
        if (cc == null) {
            throw new IllegalArgumentException("missing or invalid client id");
        }
        boolean insecureclient = !isClientSecure(cc);
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
    public TokenResponse handleClientCredential(String clientid, String clientsecret, String realm, String redirecturi, String audience, Set<String> scopes, String requestpath) {
        Client cc = _dataprovider.getClientByIdOnly(clientid);
        if (cc == null) {
            return TokenResponse.errorResponse(M3OAuthError.INVALID_CLIENT);
        }
        Set<String> responsescopes = null;
        if (scopes != null && !scopes.isEmpty()) {
            if (audience == null || audience.isBlank()) { // scope needs valid audience to be verified
                return TokenResponse.errorResponse(M3OAuthError.PARAMETER_ABSENT);
            }
            List<Client.ClientScope> matchingscopes = cc.matchingscopes(audience, scopes);
            if (matchingscopes != null && !matchingscopes.isEmpty()) {
                responsescopes = new HashSet<String>();
                for (Client.ClientScope mscp: matchingscopes) {
                    responsescopes.add(mscp.scope);
                }
            }
        }
        if (responsescopes == null) {
            return TokenResponse.errorResponse(M3OAuthError.INSUFFICIENT_SCOPE);
        }
        Long expiryseconds = Duration.ofMinutes(EXPIRY_MINUTES).get(ChronoUnit.SECONDS);
        String jwttoken = null;
        try {
            jwttoken = M3OAuth2Jwt.encodeJwtToUrlUtf8(clientid, requestpath, audience, expiryseconds, _sshkeyfile);
        } catch (Throwable t) {
            return TokenResponse.errorResponse(M3OAuthError.SERVER_ERROR);
        }
        String tokid = _dataprovider.generateTokenId();
        OAuth2AccessToken token = new OAuth2AccessToken(tokid, jwttoken, clientid, expiryseconds);
        token.setScopes(assembleScopes(responsescopes));
        _dataprovider.storeAccessToken(token);
        TokenResponse response = new TokenResponse();
        response.setToken(jwttoken);
        response.setExpires(expiryseconds);
        return response;
    }

    private String assembleScopes(Set<String> responsescopes) {
		// TODO Auto-generated method stub
        return null;
    }

    // TODO Instead of generic method to handle token, have methods for each grant type
    // as parameters could be different
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
            boolean insecureclient = !isClientSecure(cc);
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

    private boolean isClientSecure(Client client) {
        Client.Confidentiality c = client.confidentiality();
        Client.UserAgent a = client.userAgent();
        boolean secure = false;
        switch (c) {
        case TRUSTED:
        case CONFIDENTIAL:
            secure = true;
            break;
        case PUBLIC:
        default:
            secure = false;
            break;
        }
        if (!secure) return false;
        // so it may be secure; let us confirm with user agent
        switch (a) {
        case WEBSERVER:
        	secure = (c == Client.Confidentiality.TRUSTED);
            break;
        case MOBILE:
            secure = false;
            break;
        case BROWSER:
            secure = false;
        	break;
        case SERVICE:
            secure = true;
            break;
        case BATCH:
        	secure = (c == Client.Confidentiality.TRUSTED);
        	break;
        default:
            secure = false;
            break;
        }
        return secure;
    }

}
