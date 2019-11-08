package com.m3.oauth.service.data;

public interface OAuth2DataProviderFactory {
    OAuth2DataProvider create(String name, String type);
}
