package com.m3.ouath.service.data;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.m3.common.core.M3CoreHelper;
import com.m3.oauth.common.Client;

public class M3OAuthClient implements Client {
    private static final long serialVersionUID = 1L;

    private final String _id;
    private final String _secret;
    private final String _name;
    private final String _redirect_url;
    private final Confidentiality _confidentiality;
    private final UserAgent _uagent;
    private String _description;
    private String _uagentdetail;
    private final ConcurrentMap<String, List<ClientScope>> _scopes = new ConcurrentHashMap<String, List<ClientScope>>();

    public M3OAuthClient(String thename, String theid, String thesecret, String redirect_url, String client_conf, String user_agent) {
        if (client_conf == null || client_conf.length() < 6) {
            throw new IllegalArgumentException("Invalid client confidentiality " + client_conf);
        }
        try {
            _confidentiality = Confidentiality.valueOf(client_conf);
        } catch (Throwable t) {
            throw new IllegalArgumentException("Invalid client confidentiality " + client_conf, t);
        }
        if (user_agent == null || user_agent.length() < 5) {
            throw new IllegalArgumentException("Invalid user agent " + user_agent);
        }
        try {
            _uagent = UserAgent.valueOf(user_agent);
        } catch (Throwable t) {
            throw new IllegalArgumentException("Invalid user agent " + user_agent, t);
        }
        _id = theid;
        _name = thename;
        _secret = thesecret;
        _redirect_url = redirect_url;
    }

    @Override
    public String identifier() { return _id; }

    @Override
    public String secret() { return _secret; }

    @Override
    public String name() { return _name; }

    @Override
    public String description() { return _description; }
    public void setDescription(String value) { _description = value; }

    @Override
    public String redirecturl() { return _redirect_url; }

    @Override
    public Confidentiality confidentiality() { return _confidentiality; }

    @Override
    public UserAgent userAgent() { return _uagent; }

    public String userAgentDetail() { return _uagentdetail; }
    public void userAgentDetail(String value) { _uagentdetail = value; }

    @Override
    public Map<String, List<ClientScope>> allscopes() {
        Map<String, List<ClientScope>> retval = new HashMap<String, List<ClientScope>>();
        _scopes.forEach((key, value) -> {
            retval.put(key, Collections.unmodifiableList(value));
        });
        Map<String, List<ClientScope>> retval2 = Collections.unmodifiableMap(retval);
        retval.clear();
        return retval2;
    }

    @Override
    public List<ClientScope> servicescopes(String aservice) {
        return Collections.unmodifiableList(_scopes.get(aservice));
    }

    @Override
    public List<ClientScope> matchingscopes(String aservice, Set<String> requestscopes) {
        List<ClientScope> retval = Collections.unmodifiableList(_scopes.get(aservice));
        for (ListIterator<ClientScope> it = retval.listIterator(); it.hasNext(); ) {
            ClientScope scp = it.next();
            for (String reqscp : requestscopes) {
                if (!scp.scope.startsWith(reqscp)) {
                    it.remove();
                }
            }
        }
        return retval;
    }

    public ClientScope addScope(String aservice, String ascope) {
        ClientScope scp = new ClientScope(aservice, ascope);
        List<ClientScope> currscopes = _scopes.get(aservice);
        if (currscopes == null) {
            currscopes = new ArrayList<ClientScope>();
            synchronized (_scopes) {
                _scopes.put(aservice, currscopes);
            }
        }
        synchronized (currscopes) {
            currscopes.add(scp);
        }
        return scp;
    }

    String scopesAsString() {
        if (_scopes.isEmpty()) return null;
        synchronized (_scopes) {
            StringBuilder sb = new StringBuilder();
            boolean firsttime1 = true;
            for (Map.Entry<String, List<ClientScope>> me : _scopes.entrySet()) {
                if (firsttime1) firsttime1 = false;
                else sb.append(",");
                sb.append(me.getKey());
                sb.append(":");
                boolean firsttime2 = true;
                for (ClientScope cs : me.getValue()) {
                    if (firsttime2) firsttime2 = false;
                    else sb.append(" ");
                    sb.append(cs.scope);
                }
            }
            return sb.toString();
        }
    }

    void setScopesFromString(String scopesstr) {
        if (scopesstr != null && !scopesstr.isBlank()) {
        	_scopes.values().forEach(lscp -> lscp.clear());
        	_scopes.clear();
            M3CoreHelper.convertDelimitedStringToMap(scopesstr, ",", ":", _scopes, this::parseCreateListScopes);
        }
    }

    @Override
    public int compareTo(Client o) {
        return _id.compareTo(o.identifier());
    }

    public void setAdditionalInformation(String string) {
		// TODO Auto-generated method stub
		
    }

    private List<ClientScope> parseCreateListScopes(String service, String delimscopestr) {
        List<ClientScope> cltscopes = new ArrayList<ClientScope>();
        M3CoreHelper.convertDelimitedStringToList(delimscopestr, " ", service, cltscopes, this::parseCreateClientScope);
        return cltscopes;
    }

    private ClientScope parseCreateClientScope(String service, String scope) {
        return new ClientScope(service, scope);
    }

}
