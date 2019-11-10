package com.m3.ouath.service;

import java.util.Map;

import com.m3.oauth.service.data.OAuth2DataProvider;
import com.m3.oauth.service.data.OAuth2DataProviderFactory;
import com.m3.ouath.service.data.M3OAuth2H2MemoryDataProvider;

class M3OAuth2DataProviderFactory implements OAuth2DataProviderFactory {
    @Override
    public OAuth2DataProvider create(String name, String type, Map<String, Object> props) {
        if ("h2mem".equals(type)) {
            M3OAuth2H2MemoryDataProvider h2memdp = new M3OAuth2H2MemoryDataProvider(name);
            // TODO post initialization stuff
            return h2memdp;
        }
        return null;
    }
}
