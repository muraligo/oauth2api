package com.m3.oauth.common;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

public interface Client extends Serializable, Comparable<Client> {
    String identifier();
    String secret();
    String name();
    String description();
    String redirecturl();
    Confidentiality confidentiality();
    UserAgent userAgent();
    Map<String, List<ClientScope>> allscopes();
    List<ClientScope> servicescopes(String aservice);
    List<ClientScope> matchingscopes(String aservice, String scopeprefix);

    public class ClientScope {
        public final String service;
        public final String scope;
        public ClientScope(String aservice, String ascope) {
            service = aservice;
            scope = ascope;
        }
    }

    public enum Confidentiality {
        PUBLIC,
        CONFIDENTIAL,
        TRUSTED
    }

    public enum UserAgent {
        WEBSERVER,
        MOBILE,
        BROWSER,
        SERVICE,
        BATCH
    }
}
