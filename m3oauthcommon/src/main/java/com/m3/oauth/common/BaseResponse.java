package com.m3.oauth.common;

import java.util.concurrent.ConcurrentSkipListSet;

public abstract class BaseResponse {
    protected ConcurrentSkipListSet<M3OAuthError> _errors = new ConcurrentSkipListSet<M3OAuthError>();

    protected SuccessResponseType _successresponse = null;

    protected BaseResponse(SuccessResponseType typ) {
        _successresponse = typ;
    }

    public void addError(M3OAuthError err) { _errors.add(err); }
    public boolean hasErrors() { return !_errors.isEmpty(); }
    public String buildErrorResponse() {
        return null;
    }

    public enum SuccessResponseType {
        OK,
        REDIRECT
    }

    public enum M3OAuthError {
        UNKNOWN("Unknown error calling OAuth")
        ;

        private String _message;

        private M3OAuthError(String msg) {
            _message = msg;
        }

        public String message() { return _message; }
    }
}
