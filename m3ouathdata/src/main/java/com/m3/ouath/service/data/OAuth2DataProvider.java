package com.m3.ouath.service.data;

import com.m3.oauth.common.Client;
import com.m3.oauth.common.Service;

public interface OAuth2DataProvider {
    Client getClientByIdOnly(String clientid);
    Client getClientByIdSecret(String clientid, String clientsecret);
    // register a new client in context of access to scopes to a service
    Client registerClient(String thename, String redirecturl, String service, String[] initialscopes);
    Service registerService(String name, String[] initialscopes);
}
