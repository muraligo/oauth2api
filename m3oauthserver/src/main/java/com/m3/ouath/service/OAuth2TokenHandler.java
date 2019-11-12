package com.m3.ouath.service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.m3.common.core.HttpHelper;
import com.m3.common.oauth2.api.OAuth2;
import com.m3.oauth.common.M3Jwt;
import com.m3.oauth.common.AuthorizationService.TokenResponse;
import com.m3.oauth.common.BaseResponse.M3OAuthError;
import com.m3.oauth.service.data.OAuth2DataProvider;
import com.m3.ouath.service.handler.OAuth2ApiHandler;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

/**
 * There are some OAuth flows that are only 2-legged where the 
 * requestor credentials and resource servers are pre-registered 
 * with the IdP. In this case it is therefore just a 2-legged 
 * OAuth flow and therefore this handler only handles providing tokens.
 * 
 * @author museg
 *
 */
class OAuth2TokenHandler implements HttpHandler {
    private static final Logger _LOG = LoggerFactory.getLogger(OAuth2TokenHandler.class.getSimpleName());

    private final OAuth2ApiHandler _apihandler;
    private final String _basepath;

    OAuth2TokenHandler(OAuth2DataProvider dp, String rootpath, String sshkeyfile) {
        _apihandler = new OAuth2ApiHandler(dp, sshkeyfile);
        if (rootpath.endsWith("/")) {
            int slashix = rootpath.lastIndexOf('/');
            rootpath = (slashix <= 0) ? "" : rootpath.substring(0, slashix);
        }
        _basepath = rootpath + "/token";
    }

    public final String basepath() { return _basepath; }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        URI requestURI = exchange.getRequestURI();
        Headers hdrs = exchange.getRequestHeaders();
        String mthd = exchange.getRequestMethod();
        String path = null;
        if (!requestURI.isAbsolute() && !requestURI.isOpaque()) {
            path = requestURI.getPath();
            path = (path != null && !path.isBlank()) ? path.toLowerCase() : "";
        }
        TokenResponse tokenresponse = null;
        if (path == null || path.isBlank()) {
            tokenresponse = TokenResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
            sendErrorResponse(exchange, tokenresponse, null);
            _LOG.error("A non-blank base path is a must for every resource");
            return;
        }
        int pthix = path.indexOf(_basepath);
        if (pthix < 0) {
            tokenresponse = TokenResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
            sendErrorResponse(exchange, tokenresponse, null);
            _LOG.error("This resource class only handles requests with its base path");
            return;
        }
        pthix += _basepath.length();
        Map<String, String> formParams = null;
        if ("GET".equalsIgnoreCase(mthd)) {
            // do not care about Content-Type header
            if (path.charAt(pthix) != '?') {
                tokenresponse = TokenResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
                sendErrorResponse(exchange, tokenresponse, null);
                _LOG.error("A GET request must have URL encoded parameters in the path");
                return;
            }
            String qrystr = null;
            if (pthix > 0) {
                qrystr = path.substring(pthix+1);
            }
            if (qrystr == null || qrystr.isBlank()) {
                tokenresponse = TokenResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
                sendErrorResponse(exchange, tokenresponse, null);
                _LOG.error("A GET request must have URL encoded parameters in the path");
                return;
            }
            try {
                formParams = HttpHelper.parseUrlQuery(qrystr);
            } catch (UnsupportedEncodingException e) {
                tokenresponse = TokenResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
                sendErrorResponse(exchange, tokenresponse, null);
                _LOG.error("A GET request must have URL encoded parameters in the path");
                return;
            }
        } else if ("POST".equalsIgnoreCase(mthd)) {
            List<String> contentTypeLst = null;
            String contentType = null;
            if (hdrs.isEmpty() || !hdrs.containsKey(HttpHelper.HEADER_CONTENT_TYPE)) {
                tokenresponse = TokenResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
                sendErrorResponse(exchange, tokenresponse, null);
                _LOG.error("This kind of request must contain a Content-Type Header with at least a Content-Type");
                return;
            } else {
                contentTypeLst = hdrs.get(HttpHelper.HEADER_CONTENT_TYPE);
            }
            if (contentTypeLst != null && !contentTypeLst.isEmpty()) {
                contentType = contentTypeLst.get(0); // first element must be the real content type
            }
            if (contentTypeLst == null || contentTypeLst.isEmpty() || contentType == null || 
                    !HttpHelper.CONTENT_TYPE_FORM_URL_ENCODED.equalsIgnoreCase(contentType)) {
                tokenresponse = TokenResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
                sendErrorResponse(exchange, tokenresponse, null);
                _LOG.error("Methods with FORM parameters must have Content-Type Header of type URL encoded");
                return;
            }
            try (InputStream is = exchange.getRequestBody()) {
                String reqdata = null;
                while ((reqdata = HttpHelper.readLine(is)) != null) {
                    if (!reqdata.isBlank()) {
                        break;
                    }
                }
            	formParams = HttpHelper.parseUrlQuery(reqdata);
            	// remaining body should not be of consequence
            } catch (IOException ioe1) {
                tokenresponse = TokenResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
                sendErrorResponse(exchange, tokenresponse, null);
                _LOG.error("Error extracting parameters from form body");
                return;
            }
        } else {
            tokenresponse = TokenResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
            sendErrorResponse(exchange, tokenresponse, null);
            _LOG.error("This resource class only handles a GET or POST request");
            return;
        }
        // First extract any credentials from the header and add to the formParams
        if (hdrs.containsKey(OAuth2.AUTHORIZATION_HEADER)) {
            OAuth2.AuthorizationHeader authhdr = new OAuth2.AuthorizationHeader();
            String authval = hdrs.getFirst(OAuth2.AUTHORIZATION_HEADER);
            authhdr.decode(authval);
            if (authhdr.isEmpty()) {
                tokenresponse = TokenResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
                sendErrorResponse(exchange, tokenresponse, "Authorization header provided but is empty or invalid");
                _LOG.error("Authorization header provided but is empty or invalid");
                return;
            }
            formParams.put("principal", authhdr.principal());
            formParams.put("credential", authhdr.credential());
            if (authhdr.realm() != null && !authhdr.realm().isBlank()) {
                formParams.put("realm", authhdr.realm());
            }
        }
        // validate all required parameters
        String responseType = formParams.get(OAuth2.GRANT_TYPE);
        responseType = (responseType != null && responseType.isBlank()) ? null : responseType.strip();
        OAuth2.GrantType granttype = OAuth2.GrantType.getMe(responseType);
        if (granttype == null || OAuth2.GrantType.IMPLICIT.equals(granttype)) {
            tokenresponse = TokenResponse.errorResponse(M3OAuthError.UNSUPPORTED_GRANT_TYPE);
            sendErrorResponse(exchange, tokenresponse, null);
            return;
        }
        switch (granttype) {
        case CLIENT_CREDENTIALS:
            if (formParams.containsKey(OAuth2.ASSERTION_TYPE)) {
                // we only support JWT assertion type; ensure it is and then proceed
                String atval = formParams.get(OAuth2.ASSERTION_TYPE);
                if (atval == null || atval.isBlank() || !OAuth2.ASSERT_TYPE_JWT_CLIENT_CREDENTIALS.equals(atval.strip())) {
                    tokenresponse = TokenResponse.errorResponse(M3OAuthError.INVALID_GRANT);
                    sendErrorResponse(exchange, tokenresponse, "Invalid assertion type");
                    return;
                }
                // if JWT we expect to have the audience
                String audience = null;
                if (formParams.containsKey(M3Jwt.AUDIENCE)) {
                    audience = formParams.get(M3Jwt.AUDIENCE);
                    if (audience != null && audience.isBlank()) audience = null;
                }
                String redirecturi = null;
                if (formParams.containsKey(OAuth2.REDIRECT_URI)) {
                    redirecturi = formParams.get(OAuth2.REDIRECT_URI);
                    if (redirecturi != null && redirecturi.isBlank()) redirecturi = null;
                }
                Set<String> extscopes = TokenResponse.extractScopes(formParams.get(OAuth2.SCOPE));
                try {
                    String calledpath = (path.charAt(pthix) == '?') ? path.substring(0, pthix) : path;
                    tokenresponse = _apihandler.handleClientCredential(formParams.get("principal"), 
                            formParams.get("credential"), formParams.get("realm"), redirecturi, 
                            audience, extscopes, calledpath);
                } catch (Throwable t) {
                	tokenresponse = TokenResponse.errorResponse();
                    if (t instanceof IllegalArgumentException) {
                    	tokenresponse.addError(M3OAuthError.INVALID_REQUEST);
                    } else if (t instanceof IllegalStateException) {
                        if (t.getMessage().startsWith("unacceptable")) {
                        	tokenresponse.addError(M3OAuthError.UNSUPPORTED_RESPONSE_TYPE);
                        } else if (t.getMessage().startsWith("unauthorized")) {
                        	tokenresponse.addError(M3OAuthError.ACCESS_DENIED);
                        } else {
                        	tokenresponse.addError(M3OAuthError.INVALID_REQUEST);
                        }
                    }
                }
            }
            break;
        case JWT_BEARER:
            break;
        case REFRESH_TOKEN:
            break;
        case PASSWORD:
            break;
        default:
            break;
        }
    }

    

    // TODO pass in state (even if not determined by then and are null)
    public void sendErrorResponse(HttpExchange exchange, TokenResponse errors, String message) {
        String finalmsg = errors.lastError(message); // TODO pass in state
        int msglen = (finalmsg != null) ? finalmsg.length() : -1;
        try {
            exchange.sendResponseHeaders(errors.errorCode(), msglen);
        } catch (IOException ioe1) {
            _LOG.error(finalmsg);
            return;
        }
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(finalmsg.getBytes());
        } catch (IOException ioe2) {
            _LOG.error(finalmsg);
            return;
        }
        // should implicitly close request Input Stream if it was opened
    }

}
