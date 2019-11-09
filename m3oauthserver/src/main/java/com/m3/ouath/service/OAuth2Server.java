package com.m3.ouath.service;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.m3.common.core.HttpHelper;
import com.m3.oauth.service.data.OAuth2DataProvider;
import com.m3.oauth.service.data.OAuth2DataProviderFactory;
import com.sun.net.httpserver.HttpServer;

public class OAuth2Server {
    private static final Logger _LOG = LoggerFactory.getLogger(OAuth2Server.class);

    private static final String DEFAULTENV = "dev";
    private static final String SERVICENAME = "OAuth2API";

    private static OAuth2DataProviderFactory _dpfactory = null;
    static OAuth2DataProvider _dataprovider = null; // pkg private for testing
    static String _sshkeyfile = null; // pkg private for testing
    private static String _envname = null;

    private int _minThreads;
    private int _maxThreads;
    private int _adminMinThreads;
    private int _adminMaxThreads; // Should be > 1.5 times the number of cores
    private int _shutdownGracePeriod;
    private String _rootPath;

    public static void main(String[] args) {
        String argenvvalue = null;
        String argconfigpthstr = null;
        for (int ix = 0; ix < args.length; ix++) {
            if (args[ix].startsWith("--environment")) {
                argenvvalue = fetchArgumentValue("--environment", args[ix]);
            } else if (args[ix].startsWith("--config")) {
                argconfigpthstr = fetchArgumentValue("--config", args[ix]);
            } else {
                _LOG.error(SERVICENAME + ": ERROR invalid argument [" + args[ix] + " at " + ix + "].");
            }
        }
        // TODO Ensure arguments exist and are valid paths
        if (argconfigpthstr == null || argconfigpthstr.isEmpty()) {
            _LOG.error(SERVICENAME + ": Empty or invalid configuration path parameter");
            System.exit(-1);
        }
        _envname = (argenvvalue != null) ? argenvvalue.trim().toLowerCase() : DEFAULTENV;

        _LOG.info("Configuring " + SERVICENAME + " for environment [" + _envname + "] from source [" + argconfigpthstr + "]");
        OAuth2Server svc = new OAuth2Server();
        svc.readConfigs(argconfigpthstr);

        _LOG.info("Starting " + SERVICENAME + " ...");
        HttpServer server = null;
        try {
            InetSocketAddress isa = new InetSocketAddress("localhost", 8085); // TODO ENHANCE later svc._applicationConnectors.get(0).getPort());
//            InetSocketAddress isa = new InetSocketAddress(rbws._applicationConnectors.get(0).getPort());
            _LOG.debug("Address is [" + isa.getAddress().getHostAddress() + "]/[" + isa.getPort() + "]");
            server = HttpServer.create(isa, 0); // 2nd arg is backlog
        } catch (IOException ioe1) {
            _LOG.error("Error creating HTTP server listening on port [" + 
//                            svc._applicationConnectors.get(0).getPort() // TODO ENHANCE later
                            "8085"
                            + "]. Exiting", ioe1);
            System.exit(1);
        }
        final List<HttpServer> srvlst = Collections.singletonList(server); // for shutdown hook

//        HttpContext doesitworkContext = server.createContext("/check");
//        doesitworkContext.setHandler(OAuth2Server::handleDoesItWork);
        svc.registerResources(server, _dataprovider);
        server.setExecutor(Executors.newCachedThreadPool());

        Runtime.getRuntime().addShutdownHook(new Thread() { 
            public void run() { 
                _LOG.info(SERVICENAME + ": Shutdown Hook is running !");
                srvlst.get(0).stop(svc._shutdownGracePeriod);
            }
        });

        _LOG.info("... " + SERVICENAME + " started.");
        server.start();
    }

    private void registerResources(HttpServer server, OAuth2DataProvider dp) {
        OAuth2CodeHandler codeh = new OAuth2CodeHandler(dp, _rootPath);
        server.createContext(codeh.basepath(), codeh);
        OAuth2TokenHandler tokh = new OAuth2TokenHandler(dp, _rootPath, _sshkeyfile);
        server.createContext(tokh.basepath(), tokh);
    }

	private void readConfigs(String configPath) {
        // no separate env specific and app specific config files; use configPath as full path
        Map<String, Object> configraw = HttpHelper.parseAndLoadYamlAbs(_LOG, configPath);
        if (configraw == null || configraw.isEmpty()) {
            System.err.println(SERVICENAME + ": ERROR in parsing or EMPTY configuration");
            System.exit(1);
        }
        readEnvironmentSpecificConfigs(configraw);
        readFrameworkConfigs(configraw);
        readApplicationConfigs(configraw);
    }

    @SuppressWarnings("unchecked")
    private void readEnvironmentSpecificConfigs(Map<String, Object> configraw) {
        if (configraw.containsKey("server")) {
            Map<String, Object> serverdetails = (Map<String, Object>)configraw.get("server");
            _minThreads = (Integer)serverdetails.get("minThreads");
            if (_minThreads < 0) {
                _minThreads = 1;
            }
            _maxThreads = (Integer)serverdetails.get("maxThreads");
            if (_maxThreads < 0) {
                _maxThreads = 10;
            }
            _adminMinThreads = (Integer)serverdetails.get("adminMinThreads");
            if (_adminMinThreads < 0) {
                _adminMinThreads = 1;
            }
            _adminMaxThreads = (Integer)serverdetails.get("adminMaxThreads");
            if (_adminMaxThreads < 0) {
                _adminMaxThreads = 4;
            }
            _shutdownGracePeriod = (Integer)serverdetails.get("shutdownGracePeriod");
            if (_shutdownGracePeriod < 0) {
                _shutdownGracePeriod = 30000;
            }
            // TODO ENHANCE Hardcode ports for now
//            List<Map<String, Object>> appconobj = (List<Map<String, Object>>)configraw.get("applicationConnectors");
//            for (Map<String, Object> conobj : appconobj) {
//                ConnectorConfig cc = new ConnectorConfig();
//                cc.setType((String)conobj.get("type"));
//                cc.setPort((Integer)conobj.get("port"), 19000);
//                _applicationConnectors.add(cc);
//            }
//            List<Map<String, Object>> admconobj = (List<Map<String, Object>>)configraw.get("adminConnectors");
//            for (Map<String, Object> conobj : admconobj) {
//                ConnectorConfig cc = new ConnectorConfig();
//                cc.setType((String)conobj.get("type"));
//                cc.setPort((Integer)conobj.get("port"), 19001);
//                _adminConnectors.add(cc);
//            }
            _rootPath = (String)serverdetails.get("rootPath");
            if (_rootPath == null || _rootPath.isBlank())
                _rootPath = "/oauth";
            // TODO ENHANCE Handle flexible logging later
//            if (serverdetails.containsKey("requestLog")) {
//                _requestLog = readLogConfig((Map<String, Object>)configraw.get("requestLog"));
//            }
        }
    }

    @SuppressWarnings("unchecked")
    private void readApplicationConfigs(Map<String, Object> configraw) {
        if (!configraw.containsKey(_SECKEY)) return;
        Map<String, Object> configsec = (Map<String, Object>) configraw.get(_SECKEY);
        if (!configsec.containsKey(_IDPKEY)) return;
        Map<String, Object> configidp = (Map<String, Object>) configraw.get(_IDPKEY);
        _sshkeyfile = (String) configidp.get(_K_PRIVKEYFILE);
        if (configidp.containsKey(_K_DSROOT)) {
            _dpfactory = new M3OAuth2DataProviderFactory();
            _dataprovider = OAuth2DataProvider.initialize((Map<String, Object>) configraw.get(_K_DSROOT), _dpfactory);
        }
    }

    private void readFrameworkConfigs(Map<String, Object> configraw) {
        if (configraw.containsKey("monitoring")) {
            // TODO Implement monitoring later
//            Map<String, Object> monitordetails = (Map<String, Object>)configraw.get("monitoring");
//            _monitorfw = SkinnyFrameworks.addFrameworkFromConfig("MONITOR", monitordetails, _LOG);
        }
    }

    private static String fetchArgumentValue(String argname, String argraw) {
        String argvalue = null;
        int valix = argraw.indexOf("=");
        if (valix > 0) {
            valix++;
            argvalue = argraw.substring(valix);
        }
        return argvalue;
    }

    private static final String _SECKEY = "security";
    private static final String _IDPKEY = "idp";
    private static final String _K_PRIVKEYFILE = "privatekeyfile";
    private static final String _K_DSROOT = "datasource";

    /*
     * This how REDIRECTs need to be returned
private static void respondRedirect(HttpExchange httpExchange) throws IOException {
    byte[] respBody = "Metrics are provided on the /metrics endpoint.".getBytes("UTF-8");
    httpExchange.getResponseHeaders().add("Location", "/metrics");
    httpExchange.getResponseHeaders().put("Context-Type", Collections.singletonList("text/plain; charset=UTF-8"));
    httpExchange.sendResponseHeaders(302, respBody.length);
    httpExchange.getResponseBody().write(respBody);
    httpExchange.getResponseBody().close();
}
public void handle (HttpExchange t) throws IOException {
    InputStream is = t.getRequestBody();
    while (is.read () != -1) ;
    is.close();
    t.sendResponseHeaders(200, -1);
    HttpPrincipal p = t.getPrincipal();
    if (!p.getUsername().equals(USERNAME)) {
        error = true;
    }
    if (!p.getRealm().equals(REALM)) {
        error = true;
    }
    t.close();
}
static void proxyReply (HttpExchange exchange, String reply)
        throws IOException
{
    exchange.getResponseHeaders().add("Proxy-Authenticate", reply);
    exchange.sendResponseHeaders(407, 0);
}
public static void main(String[] args) throws Exception {

    HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
    //Create the context for the server.
    server.createContext("/", new BaseHandler());
    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
}
See following for health check and logging filters 
https://gist.github.com/tomwhoiscontrary/b4888b86057c74a636c455235c756354
      */

}
