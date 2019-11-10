package com.m3.oauth.service.data;

import java.util.Map;

public interface OAuth2DataProviderFactory {
    OAuth2DataProvider create(String name, String type, Map<String, Object> props);
}
