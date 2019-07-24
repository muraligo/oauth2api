package com.m3.ouath.service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.m3.common.core.HttpHelper;
import com.m3.common.oauth2.api.OAuth2;
import com.m3.oauth.common.AuthorizationService.AuthorizationResponse;
import com.m3.oauth.common.BaseResponse.M3OAuthError;
import com.m3.ouath.service.data.OAuth2DataProvider;
import com.m3.ouath.service.handler.OAuth2ApiHandler;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

public class OAuth2CodeHandler implements HttpHandler {
    private static final Logger _LOG = LoggerFactory.getLogger(OAuth2CodeHandler.class.getSimpleName());

    private final OAuth2ApiHandler _apihandler;
    private final String _basepath;

    public OAuth2CodeHandler(OAuth2DataProvider dp, String rootpath) {
        _apihandler = new OAuth2ApiHandler(dp);
        if (rootpath.endsWith("/")) {
            int slashix = rootpath.lastIndexOf('/');
            rootpath = (slashix <= 0) ? "" : rootpath.substring(0, slashix);
        }
        _basepath = rootpath + "/auth";
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
        AuthorizationResponse authresponse = null;
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
        if (path == null || path.isBlank()) {
            authresponse = AuthorizationResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
            sendErrorResponse(exchange, authresponse, null);
            _LOG.error("A non-blank base path is a must for every resource");
            return;
        }
        int pthix = path.indexOf(_basepath);
        if (pthix < 0) {
            authresponse = AuthorizationResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
            sendErrorResponse(exchange, authresponse, null);
            _LOG.error("This resource class only handles requests with its base path");
            return;
        }
        pthix += _basepath.length();
        Map<String, String> formParams = null;
        if ("GET".equalsIgnoreCase(mthd)) {
            // do not care about Content-Type header
            if (path.charAt(pthix) != '?') {
                authresponse = AuthorizationResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
                sendErrorResponse(exchange, authresponse, null);
                _LOG.error("A GET request must have URL encoded parameters in the path");
                return;
            }
            String qrystr = null;
            if (pthix > 0) {
                qrystr = path.substring(pthix+1);
            }
            if (qrystr == null || qrystr.isBlank()) {
                authresponse = AuthorizationResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
                sendErrorResponse(exchange, authresponse, null);
                _LOG.error("A GET request must have URL encoded parameters in the path");
                return;
            }
            try {
                formParams = HttpHelper.parseUrlQuery(qrystr);
            } catch (UnsupportedEncodingException e) {
                authresponse = AuthorizationResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
                sendErrorResponse(exchange, authresponse, null);
                _LOG.error("A GET request must have URL encoded parameters in the path");
                return;
            }
        } else if ("POST".equalsIgnoreCase(mthd)) {
            List<String> contentTypeLst = null;
            String contentType = null;
            if (hdrs.isEmpty() || !hdrs.containsKey(HttpHelper.HEADER_CONTENT_TYPE)) {
                authresponse = AuthorizationResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
                sendErrorResponse(exchange, authresponse, null);
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
                authresponse = AuthorizationResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
                sendErrorResponse(exchange, authresponse, null);
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
                authresponse = AuthorizationResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
                sendErrorResponse(exchange, authresponse, null);
                _LOG.error("Error extracting parameters from form body");
                return;
            }
        } else {
            authresponse = AuthorizationResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
            sendErrorResponse(exchange, authresponse, null);
            _LOG.error("This resource class only handles a GET or POST request");
            return;
        }
        // validate all required parameters
        String responseType = formParams.get(OAuth2.RESPONSE_TYPE);
        responseType = (responseType != null && responseType.isBlank()) ? null : responseType.strip(); 
        if (responseType == null || !"code".equalsIgnoreCase(responseType)) {
            authresponse = AuthorizationResponse.errorResponse(M3OAuthError.INVALID_REQUEST);
            sendErrorResponse(exchange, authresponse, 
                    "Invalid response type");
            // TODO validate to make sure it is the correct error we are returning
            return;
        }
        String clientid = formParams.get(OAuth2.CLIENT_ID);
        clientid = (clientid != null && clientid.isBlank()) ? null : clientid.strip();
        String redirecturi = formParams.get(OAuth2.REDIRECT_URI);
        redirecturi = (redirecturi != null && redirecturi.isBlank()) ? null : redirecturi.strip();
        String scope = formParams.get(OAuth2.SCOPE);
        scope = (responseType != null && scope.isBlank()) ? null : scope.strip();
        String state = formParams.get(OAuth2.STATE);
        state = (state != null && state.isBlank()) ? null : state.strip();
        String challenge = formParams.get("code_challenge");
        challenge = (challenge != null && challenge.isBlank()) ? null : challenge.strip();
        String algorithm = formParams.get("code_challenge_method");
        algorithm = (algorithm != null && algorithm.isBlank()) ? null : algorithm.strip();
        String[] scopes = scope.split(" ");
        try {
        	authresponse = _apihandler.handleAuthorizationCode(clientid, redirecturi, state, challenge, algorithm, scopes);
        } catch (Throwable t) {
            authresponse = AuthorizationResponse.errorResponse();
            if (t instanceof IllegalArgumentException) {
                authresponse.addError(M3OAuthError.INVALID_REQUEST);
            } else if (t instanceof IllegalStateException) {
                if (t.getMessage().startsWith("unacceptable")) {
                    authresponse.addError(M3OAuthError.UNSUPPORTED_RESPONSE_TYPE);
                } else if (t.getMessage().startsWith("unauthorized")) {
                    authresponse.addError(M3OAuthError.ACCESS_DENIED);
                } else {
                    authresponse.addError(M3OAuthError.INVALID_REQUEST);
                }
            }
        }
        // Send the authorization response
        int responsecode = 500;
        int msglength = -1;
        StringBuilder respsb = new StringBuilder();
        /*
         * TODO Do the following
         * Set responsecode in both below cases
         * 1. If the response is supposed to be a JSON
        try {
            authresponse.toJson(respsb);
        } catch (Throwable t) {
            // TODO handle exception of conversion to JSON
        }
         * 2. If the response is supposed to be a URL encoded URL
         * Build the URL with parameters
         */
        if (respsb.length() > 0) {
        	msglength = respsb.length();
        }
    	try {
            exchange.sendResponseHeaders(responsecode, msglength);
    	} catch (IOException ioe2) {
    	    _LOG.error("Error writing response to stream", ioe2);
    	    return;
    	}
    	try (OutputStream os = exchange.getResponseBody()) {
    	    os.write(respsb.toString().getBytes());
    	} catch (IOException ioe3) {
    	    _LOG.error("Error writing response to stream", ioe3);
    	    return;
    	}
    	// should implicitly close request Input Stream if it was opened
    }

    // TODO pass in state and scope (even if not determined by then and are null)
    public void sendErrorResponse(HttpExchange exchange, AuthorizationResponse errors, String message) {
        String finalmsg = errors.buildErrorResponse(message); // TODO pass in state and scope
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
