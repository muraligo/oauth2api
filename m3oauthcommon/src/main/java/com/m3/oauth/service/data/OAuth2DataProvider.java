package com.m3.oauth.service.data;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

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
            String name = (String)configds.get("name");
            String thetype = (String)configds.get("type");
            Map<String, Object> dpprops = new HashMap<String, Object>();
            for (Map.Entry<String, Object> dpconfprops : configds.entrySet()) {
                if ("name".equals(dpconfprops.getKey())) continue;
                if ("type".equals(dpconfprops.getKey())) continue;
                if ("initdata".equals(dpconfprops.getKey())) continue;
                dpprops.put(dpconfprops.getKey(), dpconfprops.getValue());
            }
            OAuth2DataProvider dp = dpfactory.create(name, thetype, dpprops);
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

    final AtomicLong TOKSEQNUM = new AtomicLong(1L);

	default String generateTokenId() {
	    long timestamp = System.currentTimeMillis();
	    // 63 is the length of a long
	    // 41 is the length of digits from a timestamp in milliseconds
	    // first move the timestamp to the upper bits of a long
	    long tmp_id = timestamp << (63 - 41);
	    long nodeid = 1L; // TODO this should ideally be passed in based on which node this instance is running on
	    // next move the nodeid to occupy the next 10 bits
	    tmp_id |= nodeid << (63 - 41 - 10);
	    long seqnum = TOKSEQNUM.getAndIncrement();
	    // lowest bits are taken by sequence number
	    tmp_id |= seqnum;
	    return Long.toString(tmp_id);
	}
}
