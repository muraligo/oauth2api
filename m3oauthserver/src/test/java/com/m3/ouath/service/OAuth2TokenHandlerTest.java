package com.m3.ouath.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.m3.common.core.HttpHelper;
import com.m3.common.oauth2.api.OAuth2;
import com.m3.oauth.service.data.OAuth2DataProvider;
import com.m3.oauth.service.data.OAuth2DataProviderFactory;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

@ExtendWith(MockitoExtension.class)
class OAuth2TokenHandlerTest {
    private static Logger _LOG = LoggerFactory.getLogger(OAuth2TokenHandlerTest.class);

    // test data
    private static final String VALID_PATH = "/sampleservice/sampletarget1";
    private static final String[] VALID_SCOPES = { "rama", "ding" };
    private static final String INVALID_PATH = "/sampleservice2/invalidpath";
    private static final String[] INVALID_SCOPES_1 = { "lana", "nigd" };

    // initialization data
    private static final String _SECKEY = "security";
    private static final String _IDPKEY = "idp";
    private static final String _K_PRIVKEYFILE = "privatekeyfile";
    private static final String _K_DSROOT = "datasource";
    private static OAuth2DataProviderFactory _dpfactory = null;
    private static OAuth2DataProvider _dataprovider = null;
    private static String _sshkeyfile = null;
    private static OAuth2TokenHandler _serviceundertest = null;

    private HttpExchange exchange = null;

    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        readConfigs("E:\\Projects\\Eclipse\\mysamples\\oauth2service\\m3oauthserver\\src\\test\\resources\\conf\\idp_dev.yaml");
        _serviceundertest = new OAuth2TokenHandler(_dataprovider, "/auth", _sshkeyfile);
        _LOG.debug("Static initialization complete");
    }

    @AfterAll
    static void tearDownAfterClass() throws Exception {
    }

    @BeforeEach
    void setUp() throws Exception {
        exchange = Mockito.mock(HttpExchange.class, withSettings().lenient().defaultAnswer(RETURNS_SMART_NULLS));
    }

    @AfterEach
    void tearDown() throws Exception {
    }

    @Test
    void handlePostWithValidClientValidPathValidScopeSucceeds() {
        URI expecturi = null;
        try {
            expecturi = new URI("http", null, "localhost", 8495, "/oauth/token", null, null);
        } catch (URISyntaxException ex) {
            fail("OAuth2TokenHandlerTest: Setup URI failed", ex);
        }
        Headers httpreqhdrs = new Headers();
        httpreqhdrs.put(OAuth2.AUTHORIZATION_HEADER, Collections.singletonList(buildValidTokenRequestAuthHeader()));
        httpreqhdrs.put(HttpHelper.HEADER_CONTENT_TYPE, Collections.singletonList(HttpHelper.CONTENT_TYPE_FORM_URL_ENCODED));
        when(exchange.getRequestURI()).thenReturn(expecturi);
        when(exchange.getRequestHeaders()).thenReturn(httpreqhdrs);
        when(exchange.getRequestMethod()).thenReturn("POST");
        String bodycontent = buildRequestBodyContent(VALID_PATH, VALID_SCOPES);
        InputStream is = new ByteArrayInputStream(bodycontent.getBytes());
        when(exchange.getRequestBody()).thenReturn(is);
        // TODO the doAnswer for sendResponseHeaders
        // TODO the when for getResponseBody
        try {
            _serviceundertest.handle(exchange);
        } catch (IOException ioe) {
            fail("OAuth2TokenHandlerTest: Exception unhandled in call to handle", ioe);
        }
        // TODO Asserts
        fail("Not yet implemented");
    }

    private String buildValidTokenRequestAuthHeader() {
		// TODO Auto-generated method stub
        return null;
    }

    private String buildRequestBodyContent(String path, String[] scopearr) {
        StringBuilder scopesb = new StringBuilder();
        boolean firsttime = true;
        for (int scpix = 0; scpix < scopearr.length; scpix++) {
            if (firsttime) firsttime = false;
            else scopesb.append(" ");
            scopesb.append(scopearr[scpix]);
        }
        String scopestr = scopesb.toString();
        // TODO complete the rest of the request
        return null;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> readConfigs(String configPath) {
        Map<String, Object> configraw = null;
        try {
            configraw = HttpHelper.parseAndLoadYamlAbs(_LOG, configPath);
        } catch (Throwable t) {
            _LOG.error("ERROR in parsing or EMPTY configuration", t);
            fail("OAuth2TokenHandlerTest: ERROR in parsing or EMPTY configuration", t);
        }
        if (configraw == null || configraw.isEmpty()) {
            _LOG.error("ERROR in parsing or EMPTY configuration");
            fail("OAuth2TokenHandlerTest: ERROR in parsing or EMPTY configuration");
        }
        // skip ser stuff for testing
        if (!configraw.containsKey(_SECKEY)) return configraw;
		Map<String, Object> configsec = (Map<String, Object>) configraw.get(_SECKEY);
        if (!configsec.containsKey(_IDPKEY)) return configraw;
        Map<String, Object> configidp = (Map<String, Object>) configraw.get(_IDPKEY);
        _sshkeyfile = (String) configidp.get(_K_PRIVKEYFILE);
        if (configidp.containsKey(_K_DSROOT)) {
            _dpfactory = new M3OAuth2DataProviderFactory();
            _dataprovider = OAuth2DataProvider.initialize((Map<String, Object>) configraw.get(_K_DSROOT), _dpfactory);
        }
        return configraw;
    }

}
