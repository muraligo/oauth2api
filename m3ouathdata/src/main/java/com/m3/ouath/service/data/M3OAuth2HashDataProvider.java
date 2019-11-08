package com.m3.ouath.service.data;

import java.util.List;

import com.m3.oauth.common.AccessToken;
import com.m3.oauth.common.Client;
import com.m3.oauth.common.Service;
import com.m3.oauth.service.data.OAuth2DataProvider;

class M3OAuth2HashDataProvider implements OAuth2DataProvider {
    private final String _name;

    M3OAuth2HashDataProvider(String thename) {
        _name = thename;
    }

    @Override
    public Client getClientByIdOnly(String clientid) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Client getClientByIdSecret(String clientid, String clientsecret) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Client registerClient(String thename, String redirecturl, String service, String[] initialscopes) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Service registerService(String name, String[] initialscopes) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void storeAccessToken(AccessToken token) {
        // TODO Auto-generated method stub
    }

    @Override
    public void initializeWithData(List<ClientData> clientData) {
        // TODO Auto-generated method stub
    }

    public String name() { return _name; }
}
