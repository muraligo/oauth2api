package com.m3.oauth.common;

import java.util.concurrent.ConcurrentSkipListSet;

public abstract class BaseResponse {
    protected ConcurrentSkipListSet<M3OAuthError> _errors = new ConcurrentSkipListSet<M3OAuthError>();

    protected SuccessResponseType _successresponse = null;

    protected BaseResponse(SuccessResponseType typ) {
        _successresponse = typ;
    }

    public int errorCode() {
        return hasErrors() ? _errors.last().code() : 200;
    }
    public String lastError(String msg) {
        return hasErrors() ? _errors.last().toPartialJson(msg) : null;
    }
    public void addError(M3OAuthError err) { _errors.add(err); }
    public boolean hasErrors() { return !_errors.isEmpty(); }
    public String errorsToString(String msg) {
    	StringBuilder sb = new StringBuilder();
    	final int errsz = _errors.size();
        if (hasErrors()) {
            if (errsz > 1) {
                sb.append("{ \"errors\": [ ");
            }
            _errors.forEach(err -> {
            	sb.append(err.toPartialJson(msg));
                if (errsz > 1) {
                	sb.append(", ");
                }
            });
            if (errsz > 1) {
                sb.append("] }");
            }
        }
        return (sb == null || sb.length() == 0) ? null : sb.toString();
    }

    public enum SuccessResponseType {
        OK,
        REDIRECT
    }

    public enum M3OAuthError {
        // TODO get the correct error code here
        UNKNOWN(500, "Unknown error calling OAuth"),
        UNSUPPORTED_OVER_HTTP(400, "OAuth 2.0 only supports calls over HTTPS"),
        VERSION_REJECTED(400, "Supplied version of OAuth is not supported"),
        PARAMETER_ABSENT(400, "A required parameter is missing from the request"),
        PARAMETER_REJECTED(400, "A supplied parameter is too long"),
        // The request is missing a required parameter, or is otherwise malformed.
        // Includes an unsupported parameter value. (subsumes INVALID_PARAM error)
        INVALID_REQUEST(400, "Invalid OAuth 2.0 Request"),
        // The authorization server does not support this OAuth 2.0 request using this method.
        UNSUPPORTED_RESPONSE_TYPE(400, "Clients requested response type is not supported for this request"), 
        INVALID_SCOPE(400, "The requested scope is invalid, unknown, or malformed."), 
        SERVER_ERROR(500, "Server encountered an unexpected condition which prevented it from fulfilling the request."), 
        // The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.
        TEMPORARILY_UNAVAILABLE(500, "Server is temporarily unavailable"), 
        // Client authentication failed (e.g. unknown client, no
        // client authentication included, or unsupported
        // authentication method).  The authorization server MAY
        // return an HTTP 401 (Unauthorized) status code to indicate
        // which HTTP authentication schemes are supported.  If the
        // client attempted to authenticate via the "Authorization"
        // request header field, the authorization server MUST
        // respond with an HTTP 401 (Unauthorized) status code, and
        // include the "WWW-Authenticate" response header field
        // matching the authentication scheme used by the client.
        INVALID_CLIENT(401, "Client authentication failed (e.g. unknown client, or unsupported authentication method)."),
        UNAUTHORIZED_ACCESS(401, "Client has not provided the necessary credentials to perform the necessary action."),
        UNSUPPORTED_GRANT_TYPE(401, "The authorization grant type is not supported by the authorization server."),
        // Authorization code, resource owner credentials or refresh token has the described error
        // Or the redirect URI does not match
        INVALID_GRANT(401, "The grant is expired, revoked, or otherwise invalid."), 
        INVALID_TOKEN(401, "The provided token is revoked, malformed, or othewise invalid."), 
        TOKEN_EXPIRED(401, "The provided token has expired, please request another."), 
        INSUFFICIENT_SCOPE(403, "The request requires higher privileges than provided by the token."),
        // Client does not have the permission necessary to perform the action.
        // The resource owner denied the request for authorization.
        ACCESS_DENIED(403, "Client is denied requested access.")
        ;

    	private final int _code;
        private final String _message;

        private M3OAuthError(int cd, String msg) {
            _code = cd;
            _message = msg;
        }

        public int code() { return _code; }
        public String message() { return _message; }
        public String errorValue() { return name().toLowerCase(); }

        public String toPartialJson(String msg) {
            StringBuilder sb = new StringBuilder("{ ");
            sb.append("\"");
            sb.append(M3ErrorFields.NAME.errorFieldName());
            sb.append("\": \"");
            sb.append(name().toLowerCase());
            sb.append("\", \"");
            sb.append(M3ErrorFields.DESCRIPTION.errorFieldName());
            sb.append("\": \"");
            sb.append(message());
            sb.append(" ");
            sb.append(msg);
            sb.append("\"");
            return sb.toString();
        }
    }

    public enum M3ErrorFields {
        NAME("error"), 
        DESCRIPTION("error_description"),
        URI("error_uri");
    
        private final String _name;
        private M3ErrorFields(String value) {
            _name = value;
        }
        public String errorFieldName() { return _name; }
    }
}
