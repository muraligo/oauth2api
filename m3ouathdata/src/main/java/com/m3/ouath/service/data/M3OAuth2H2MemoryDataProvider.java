package com.m3.ouath.service.data;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.m3.oauth.common.AccessToken;
import com.m3.oauth.common.Client;
import com.m3.oauth.common.Service;
import com.m3.oauth.service.data.OAuth2DataProvider;

public class M3OAuth2H2MemoryDataProvider implements OAuth2DataProvider {
    private static final Logger _LOG = LoggerFactory.getLogger(M3OAuth2H2MemoryDataProvider.class);

    static final String DSURL = "jdbc:h2:mem:dev";
    private static final String CLIENT_TABLE_NAME = "m3_aaa_client";
    private static final String FLD_CLIENT_ID = "client_id";
    private static final String FLD_NAME = "name";
    private static final String FLD_SECRET = "client_secret";
    private static final String FLD_REDIRECT_URL = "redirect_url";
    private static final String FLD_CLIENT_CONF = "confidentiality";
    private static final String FLD_UAGENT = "user_agent";
    private static final String FLD_RESOURCES = "resources";
    private static final String FLD_ADDL_INFO = "additional_info";
    private static final String TOKEN_TABLE_NAME = "m3_aaa_token";
    private static final String FLD_TOKEN_ID = "token_id";
    private static final String FLD_TOKEN = "token_value";
    private static final String FLD_EXPIRY = "token_expiry";
    private static final String FLD_SCOPES = "scopes";
    private static final String FLD_ENDPOINT = "endpoint";
    private static final Object FSPEC_STDSTRING = " VARCHAR2(32) NOT NULL";
    private static final Object FSPEC_NNLONGSTRING = " VARCHAR2(1024) NOT NULL";
    private static final Object FSPEC_NLLONGSTRING = " VARCHAR2(1024)";

    private final String _name;
    private Connection _conn = null;

    final AtomicLong CLT_SEQ_NUM = new AtomicLong(1L);

    PreparedStatement psclientbyidsecret = null;
    PreparedStatement psclientins = null;
    PreparedStatement pstokenins = null;
    PreparedStatement psbyid = null;

    public M3OAuth2H2MemoryDataProvider(String name) {
        _name = name;
        buildTables();
    }

    @Override
    public Client getClientByIdOnly(String clientid) {
		// TODO Auto-generated method stub
        return null;
    }

    @Override
    public Client getClientByIdSecret(String clientid, String clientsecret) {
        initializeClientQueryPs();
        ResultSet rs = null;
        M3OAuthClient cdt = null;
        try {
            psclientbyidsecret.setString(1, clientid);
            psclientbyidsecret.setString(2, clientsecret);
            rs = psclientbyidsecret.executeQuery();
            if (rs != null && rs.first()) { // should only be 1 such row
                String theid = rs.getString(1);
                String thename = rs.getString(2);
                String thesecret = rs.getString(3);
                String redirect_url = rs.getString(4);
                String client_conf = rs.getString(5);
                String user_agent = rs.getString(6);
                cdt = new M3OAuthClient(thename, theid, thesecret, redirect_url, client_conf, user_agent);
                cdt.setResourceDefs(rs.getString(7));
                cdt.setAdditionalInformation(rs.getString(8));
            }
        } catch (SQLException sqle1) {
            throw new RuntimeException("ERROR executing SQL query or retrieving result to retrieve client", sqle1);
        }
        return cdt;
    }

    @Override
    public Client registerClient(String thename, String redirecturl, String service, String[] initialscopes) {
        M3OAuthClient row = getClientByNameOnly(thename);
        String resourcedefstr = null;
        if (row != null) {
        	// TODO if exists, add the service and scopes to resourceDefs
        	// TODO generate string resourceDefs and update
            return row;
        }
        String theid = generateClientId();
        String thesecret = null; // TODO generate the secret
        String client_conf = null; // TODO pass in or use default
        String user_agent = null; // TODO pass in or use default
        row = new M3OAuthClient(thename, theid, thesecret, redirecturl, client_conf, user_agent);
        // TODO generate string resourceDefs and set
        row.setResourceDefs(resourcedefstr);
        initializeClientInsertPs();
        int res = -1;
        try {
            psclientins.setString(1, row.identifier());
            psclientins.setString(2,  row.name());
            psclientins.setString(3, row.secret());
            psclientins.setString(4, row.redirecturl());
            psclientins.setString(5, row.confidentiality().name());
            psclientins.setString(6, row.userAgentDetail());
//            psclientins.setString(7, row.resourceDefs());
            res = psclientins.executeUpdate();
            if (res > 0) {
                _LOG.info("SUCCESSfully added to client. Instances impacted {}.", res);
            } else {
                final String errmsg = "ERROR adding to client. No rows added.";
                _LOG.error(errmsg);
                throw new RuntimeException(errmsg);
            }
        } catch (SQLException sqle1) {
            throw new RuntimeException("ERROR executing SQL to insert client", sqle1);
        }
        return null;
    }

    @Override
    public Service registerService(String name, String[] initialscopes) {
		// TODO Auto-generated method stub
        return null;
    }

    @Override
    public void storeAccessToken(AccessToken token) {
        initializeTokenInsertPs();
        int res = -1;
        try {
            pstokenins.setString(1, token.tokenId());
            pstokenins.setString(2, token.clientId());
            pstokenins.setString(3, token.tokenValue());
            pstokenins.setLong(4, token.tokenExpiresAfterMs());
//            pstokenins.setString(5, token.scopeAsString());
//            pstokenins.setString(6, token.endPointPath());
            res = pstokenins.executeUpdate();
            if (res > 0) {
                _LOG.info("SUCCESSfully added to token. Instances impacted {}.", res);
            } else {
                final String errmsg = "ERROR adding to token. No rows added.";
                _LOG.error(errmsg);
                throw new RuntimeException(errmsg);
            }
        } catch (SQLException sqle1) {
            throw new RuntimeException("ERROR executing SQL to insert token", sqle1);
        }
    }

    @Override
    public void initializeWithData(List<ClientData> clientData) {
		// TODO Auto-generated method stub

    }

    String name() { return _name; }

    Connection connect() {
        if (_conn == null) {
            try {
                _conn = DriverManager.getConnection(DSURL);
            } catch (SQLException sqle) {
                throw new IllegalStateException("Exception initializing access DB", sqle);
            }
        }
        if (_conn == null) {
            throw new IllegalStateException("Exception initializing access DB");
        }
        return _conn;
    }

    private M3OAuthClient getClientByNameOnly(String thename) {
        // TODO implement
        return null;
    }

    private void buildTables() {
        // client
        final String midfldprfx = ", ";
        StringBuilder sqlsb = new StringBuilder();
        sqlsb.append("CREATE TABLE ");
        sqlsb.append(CLIENT_TABLE_NAME);
        sqlsb.append(" (");
        sqlsb.append(FLD_CLIENT_ID);
        sqlsb.append(FSPEC_STDSTRING);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_NAME);
        sqlsb.append(FSPEC_STDSTRING);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_SECRET);
        sqlsb.append(" VARCHAR2(2048) NOT NULL, ");
        sqlsb.append(FLD_REDIRECT_URL);
        sqlsb.append(" VARCHAR2(1024) NOT NULL, ");
        sqlsb.append(FLD_CLIENT_CONF);
        sqlsb.append(FSPEC_STDSTRING);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_UAGENT);
        sqlsb.append(FSPEC_STDSTRING);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_RESOURCES);
        sqlsb.append(FSPEC_NNLONGSTRING);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_ADDL_INFO);
        sqlsb.append(FSPEC_NLLONGSTRING);
        sqlsb.append(midfldprfx);
        sqlsb.append("CONSTRAINT client_pk PRIMARY KEY (");
        sqlsb.append(FLD_CLIENT_ID);
        sqlsb.append("))");
        String clientsql = sqlsb.toString();
        sqlsb.delete(0, sqlsb.length());
        sqlsb.append("CREATE TABLE ");
        sqlsb.append(TOKEN_TABLE_NAME);
        sqlsb.append(" (");
        sqlsb.append(FLD_TOKEN_ID);
        sqlsb.append(FSPEC_STDSTRING);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_CLIENT_ID);
        sqlsb.append(FSPEC_STDSTRING);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_TOKEN);
        sqlsb.append(" VARCHAR2(2048) NOT NULL, ");
        sqlsb.append(FLD_EXPIRY);
        sqlsb.append(" VARCHAR2(2048), ");
        sqlsb.append(FLD_SCOPES);
        sqlsb.append(FSPEC_NLLONGSTRING);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_ENDPOINT);
        sqlsb.append(FSPEC_STDSTRING);
        sqlsb.append(midfldprfx);
        sqlsb.append("CONSTRAINT token_pk PRIMARY KEY (");
        sqlsb.append(FLD_TOKEN_ID);
        sqlsb.append("))");
        String toksql = sqlsb.toString();
        Connection conn = connect();
        if (conn == null) {
            throw new IllegalStateException("Exception connecting to access db");
        }
        int[] statuses = null;
        try (Statement stmt = conn.createStatement()) {
            stmt.addBatch(clientsql);
            stmt.addBatch(toksql);
            statuses = stmt.executeBatch();
        } catch (SQLException sqle1) {
            throw new RuntimeException("ERROR creating table for client", sqle1);
        }
        sqlsb.delete(0, sqlsb.length());
        sqlsb.append("Create Table Statuses = ");
        for (int ix = 0; ix < statuses.length; ix++) {
            sqlsb.append(", [");
            sqlsb.append(Integer.toString(statuses[ix]));
            sqlsb.append("]");
        }
        _LOG.debug(sqlsb.toString());
    }

    private void initializeClientQueryPs() {
        Connection conn = null;
        try {
            if (psclientbyidsecret != null) {
                psclientbyidsecret.clearParameters();
                psclientbyidsecret.clearWarnings();
            } else {
                conn = connect();
                if (conn == null) {
                    throw new IllegalStateException("Exception connecting to access db");
                }
                psclientbyidsecret = conn.prepareStatement(buildClientQueryString());
            }
        } catch (SQLException sqle1) {
            throw new RuntimeException("ERROR preparing SQL query to retrieve client", sqle1);
        }
    }

    private String buildClientQueryString() {
        StringBuilder sqlsb = new StringBuilder("SELECT ");
        final String alias = "ct";
        final String fldprfx = alias + ".";
        final String midfldprfx = ", " + fldprfx;
        sqlsb.append(fldprfx);
        sqlsb.append(FLD_CLIENT_ID);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_NAME);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_SECRET);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_REDIRECT_URL);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_CLIENT_CONF);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_UAGENT);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_RESOURCES);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_ADDL_INFO);
        sqlsb.append(" FROM ");
        sqlsb.append(CLIENT_TABLE_NAME);
        sqlsb.append(" AS ");
        sqlsb.append(alias);
        sqlsb.append(" WHERE ");
        sqlsb.append(fldprfx);
        sqlsb.append(FLD_CLIENT_ID);
        sqlsb.append(" = ? AND ");
        sqlsb.append(fldprfx);
        sqlsb.append(FLD_SECRET);
        sqlsb.append(" = ?");
        return sqlsb.toString();
    }

    private void initializeClientInsertPs() {
        Connection conn = null;
        try {
            if (psclientins != null) {
                psclientins.clearParameters();
                psclientins.clearWarnings();
            } else {
                conn = connect();
                if (conn == null) {
                    throw new IllegalStateException("Exception connecting to access db");
                }
                psclientins = conn.prepareStatement(buildClientInsertString());
            }
        } catch (SQLException sqle1) {
            throw new RuntimeException("ERROR preparing SQL to insert client", sqle1);
        }
    }

    private String buildClientInsertString() {
        StringBuilder sqlsb = new StringBuilder("INSERT INTO ");
        final String midfldprfx = ", ";
        sqlsb.append(CLIENT_TABLE_NAME);
        sqlsb.append(" (");
        sqlsb.append(FLD_CLIENT_ID);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_NAME);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_SECRET);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_REDIRECT_URL);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_CLIENT_CONF);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_UAGENT);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_RESOURCES);
        sqlsb.append(") VALUES (?, ?, ?, ?, ?, ?, ?)");
        return sqlsb.toString();
    }

    private void initializeTokenInsertPs() {
        Connection conn = null;
        try {
            if (pstokenins != null) {
                pstokenins.clearParameters();
                pstokenins.clearWarnings();
            } else {
                conn = connect();
                if (conn == null) {
                    throw new IllegalStateException("Exception connecting to access db");
                }
                pstokenins = conn.prepareStatement(buildTokenInsertString());
            }
        } catch (SQLException sqle1) {
            throw new RuntimeException("ERROR preparing SQL to insert token", sqle1);
        }
    }

    private String buildTokenInsertString() {
        StringBuilder sqlsb = new StringBuilder("INSERT INTO ");
        final String midfldprfx = ", ";
        sqlsb.append(TOKEN_TABLE_NAME);
        sqlsb.append(" (");
        sqlsb.append(FLD_TOKEN_ID);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_CLIENT_ID);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_TOKEN);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_EXPIRY);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_SCOPES);
        sqlsb.append(midfldprfx);
        sqlsb.append(FLD_ENDPOINT);
        sqlsb.append(") VALUES (?, ?, ?, ?, ?, ?)");
        return sqlsb.toString();
    }

    private String generateClientId() {
        long timestamp = System.currentTimeMillis();
        // 63 is the length of a long
        // 41 is the length of digits from a timestamp in milliseconds
        // the following moves the timestamp to the upper bits of a long
        long _tmp_id = timestamp << (63 - 41);
        long _nodeId = 1L;
        // the following moves the nodeId to occupy the next 10 bits
        _tmp_id |= _nodeId << (63 - 41 - 10);
        long _seqnum = CLT_SEQ_NUM.getAndIncrement();
        // the lowest bits are taken by sequence number
        _tmp_id |= _seqnum;
        return Long.toString(_tmp_id);
    }
}
