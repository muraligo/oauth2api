package com.m3.oauth.common;

public interface AccessToken {
    String tokenId();
    String clientId();
    String tokenValue();
    Long tokenExpiresAfterMs();
}
