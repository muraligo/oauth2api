package com.m3.ouath.service.handler;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.m3.oauth.common.Service;

public class M3OAuthService implements Service {
    private static final long serialVersionUID = 1L;

    private final String _id;
    private final String _name;
    private String _description;
    private final List<String> _scopes = new ArrayList<String>();

    public M3OAuthService(String theid, String aname) {
        _name = aname;
        _id = theid;
    }

    @Override
    public String identifier() { return _id; }

    @Override
    public String name() { return _name; }

    @Override
    public String description() { return _description; }
    public void setDescription(String value) { _description = value; }

    @Override
    public List<String> scopes() { return Collections.unmodifiableList(_scopes); }

    public void addScope(String ascope) {
        if (!_scopes.contains(ascope)) {
            synchronized (_scopes) {
                _scopes.add(ascope);
            }
        }
    }

    @Override
    public int compareTo(Service o) {
        return _name.compareTo(o.name());
    }

}
