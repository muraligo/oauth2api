package com.m3.oauth.service.data;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.m3.oauth.common.AccessToken;
import com.m3.oauth.common.Client;
import com.m3.oauth.common.Service;

public interface OAuth2DataProvider {
    Client getClientByIdOnly(String clientid);
    Client getClientByIdSecret(String clientid, String clientsecret);
    // register a new client in context of access to scopes to a service
    Client registerClient(String thename, String redirecturl, String service, String[] initialscopes);
    Service registerService(String name, String[] initialscopes);
    void storeAccessToken(AccessToken token);
    void initializeWithData(List<ClientData> clientData);

    @SuppressWarnings("unchecked")
    static OAuth2DataProvider initialize(Map<String, Object> configds, OAuth2DataProviderFactory dpfactory) {
        if (configds.containsKey("type")) {
            OAuth2DataProvider dp = dpfactory.create((String)configds.get("name"), (String)configds.get("type"));
            if (configds.containsKey("initdata")) {
                List<Map<String, Object>> initdatacfg = (List<Map<String, Object>>)configds.get("initdata");
                for (Map<String, Object> initvalcfg : initdatacfg) {
                    String entity = (String)initvalcfg.get("entity");
                    if ("clientdetails".equalsIgnoreCase(entity)) {
                        List<Map<String, Object>> cltdatacfg = (List<Map<String, Object>>)initvalcfg.get("values");
                        List<ClientData> clientdata = new ArrayList<ClientData>();
                        for (Map<String, Object> cltvalcfg : cltdatacfg) {
                            String id = (String)cltvalcfg.get("id");
                            String secret =  (String)cltvalcfg.get("secret");
                            String redirecturl =  (String)cltvalcfg.get("redirecturl");
                            List<Map<String, Object>> svcscpcfgs = (List<Map<String, Object>>)initvalcfg.get("resources");
                            for (Map<String, Object> svcscpcfg : svcscpcfgs) {
                                ClientData cltdata = new ClientData();
                                cltdata.id = id;
                                cltdata.secret = secret;
                                cltdata.redirecturl = redirecturl;
                                cltdata.service = (String)svcscpcfg.get("service");
                                String scpstr = (String)svcscpcfg.get("scope");
                                cltdata.scopes = scpstr.strip().split(" ");
                                clientdata.add(cltdata);
                            }
                        }
                        dp.initializeWithData(clientdata);
                    }
                }
            }
            return dp;
        }
        return null;
    }

    enum DataProviderType {
        HASH_BASED("hashds"),
        H2_INMEMORY("h2mem"),
        H2_FILE("h2file"),
        POSTGRESQL("postgres");

        private final String _configkey;
        private DataProviderType(String cfgkey) {
            _configkey = cfgkey;
        }

        public String configKey() { return _configkey; }

        public static DataProviderType fromConfigKey(String cfgkey) {
            if (cfgkey != null && !cfgkey.isBlank()) {
                for (DataProviderType dptyp : values()) {
                    if (dptyp._configkey.equalsIgnoreCase(cfgkey)) {
                        return dptyp;
                    }
                }
            }
            return null;
        }
    }

    public class ClientData {
        String id = null;
        String secret =  null;
        String redirecturl =  null;
        String service = null;
        String[] scopes = null;
    }
}
