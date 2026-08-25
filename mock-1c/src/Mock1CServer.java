import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

public class Mock1CServer {
    private static final int PORT = Integer.parseInt(System.getenv().getOrDefault("PORT", "8704"));
    private static final String APP_PATH = "/app";
    private static final String LOCALE_PATH = "ru_RU";
    private static final String VL = "ru";
    private static final String VERSION = "8.3.25.1445";
    private static final String USERNAME = System.getenv().getOrDefault("MOCK_1C_USERNAME", "zapuser");
    private static final String PASSWORD = System.getenv().getOrDefault("MOCK_1C_PASSWORD", "ZapTest123!");

    private static final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", PORT), 0);
        server.setExecutor(Executors.newCachedThreadPool());

        server.createContext(APP_PATH + "/e1cib/start", Mock1CServer::handleStart);
        server.createContext(APP_PATH + "/" + LOCALE_PATH + "/e1cib/login", Mock1CServer::handleLogin);
        server.createContext(APP_PATH + "/" + LOCALE_PATH + "/", Mock1CServer::handleLocaleHome);
        server.createContext(APP_PATH + "/api/orders", Mock1CServer::handleProtectedOrders);
        server.createContext("/RPS/hs/WMSService/messagequeue", Mock1CServer::handleProtectedMessageQueue);
        server.createContext("/openapi.json", Mock1CServer::handleOpenApi);
        server.createContext("/debug/sessions", Mock1CServer::handleDebugSessions);
        server.createContext("/debug/invalidate", Mock1CServer::handleInvalidate);
        server.createContext(APP_PATH, Mock1CServer::handleAppRoot);
        server.createContext("/", Mock1CServer::handleRoot);

        server.start();
        System.out.println("Mock 1C auth server started on http://0.0.0.0:" + PORT);
        System.out.println("Expected Docker ZAP URL: http://mock-1c:" + PORT + APP_PATH);
        System.out.println("Credentials: " + USERNAME + " / " + PASSWORD);
        System.out.println("OpenAPI (Docker): http://mock-1c:" + PORT + "/openapi.json");
    }

    private static void handleStart(HttpExchange ex) throws IOException {
        log(ex);
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            methodNotAllowed(ex, "POST");
            return;
        }

        Map<String, String> form = parseForm(readBody(ex));
        if (!USERNAME.equals(form.get("usr")) || !PASSWORD.equals(form.get("pwd"))) {
            sendText(ex, 401, "Authentication failed\n");
            return;
        }
        if (!"error".equals(form.get("authfailhandling"))) {
            sendText(ex, 400, "Expected authfailhandling=error\n");
            return;
        }

        String sid = UUID.randomUUID().toString();
        sessions.put(sid, new Session(sid));

        Headers h = ex.getResponseHeaders();
        h.set("vrs-session2", sid);
        h.set("vrs-rc", "1");
        h.set("Location", APP_PATH + "/?VRSSESSION2=" + sid + "&OIDA-");
        h.set("Content-Language", "en");
        ex.sendResponseHeaders(301, -1);
        ex.close();
    }

    private static void handleLogin(HttpExchange ex) throws IOException {
        log(ex);
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            methodNotAllowed(ex, "POST");
            return;
        }

        Query q = parseQuery(ex.getRequestURI());
        String sid = q.params.get("sid");
        String clnId = q.params.get("clnId");

        if (sid == null || !sessions.containsKey(sid)) {
            sendJson(ex, 400, "{\"error\":\"unknown sid\"}");
            return;
        }
        if (!VERSION.equals(q.params.get("version"))) {
            sendJson(ex, 400, "{\"error\":\"bad version\",\"expected\":\"" + VERSION + "\"}");
            return;
        }
        if (!VL.equals(q.params.get("vl"))) {
            sendJson(ex, 400, "{\"error\":\"bad vl\",\"expected\":\"" + VL + "\"}");
            return;
        }
        if (!q.flags.contains("nooida")) {
            sendJson(ex, 400, "{\"error\":\"missing nooida flag\"}");
            return;
        }
        if (!isUuid(clnId)) {
            sendJson(ex, 400, "{\"error\":\"clnId must be UUID\"}");
            return;
        }
        if (readBody(ex).length() != 0) {
            sendJson(ex, 400, "{\"error\":\"login body must be empty\"}");
            return;
        }

        Session session = sessions.get(sid);
        session.authenticated = true;
        session.clientId = clnId;
        session.lastSeen = Instant.now();

        // The script deliberately ignores this encoded header and uses the plain sid/seance UUID.
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("mock-1c-session:" + sid).getBytes(StandardCharsets.UTF_8));
        ex.getResponseHeaders().set("vrs-session", encoded);
        ex.getResponseHeaders().set("vrs-rc", "0");

        // Keep formatting exact: the uploaded script searches for \"seance\":\"<sid>\".
        String body = "{\"response\":{\"seance\":\"" + sid + "\",\"clientId\":\"" + clnId + "\",\"user\":\"" + escapeJson(USERNAME) + "\"}}";
        sendJson(ex, 200, body);
    }

    private static void handleAppRoot(HttpExchange ex) throws IOException {
        log(ex);
        String path = ex.getRequestURI().getPath();
        if (!(APP_PATH.equals(path) || (APP_PATH + "/").equals(path))) {
            sendText(ex, 404, "Not found\n");
            return;
        }

        Query q = parseQuery(ex.getRequestURI());
        String sid = q.params.get("VRSSESSION2");
        if (sid != null && sessions.containsKey(sid)) {
            ex.getResponseHeaders().set("Location", APP_PATH + "/" + LOCALE_PATH + "/");
            ex.sendResponseHeaders(302, -1);
            ex.close();
            return;
        }

        sendHtml(ex, 200, pageHtml());
    }

    private static void handleLocaleHome(HttpExchange ex) throws IOException {
        log(ex);
        sendHtml(ex, 200, pageHtml());
    }

    private static void handleProtectedOrders(HttpExchange ex) throws IOException {
        log(ex);
        Session s = requireSession(ex);
        if (s == null) return;
        sendJson(ex, 200, "{\"authenticated\":true,\"username\":\"" + escapeJson(USERNAME) + "\",\"orders\":[{\"id\":101,\"status\":\"READY\"}],\"seance\":\"" + s.sid + "\"}");
    }

    private static void handleProtectedMessageQueue(HttpExchange ex) throws IOException {
        log(ex);
        Session s = requireSession(ex);
        if (s == null) return;

        String path = ex.getRequestURI().getPath();
        String prefix = "/RPS/hs/WMSService/messagequeue/";
        if (!path.startsWith(prefix) || path.length() <= prefix.length()) {
            sendJson(ex, 404, "{\"error\":\"message id required\"}");
            return;
        }
        String messageId = path.substring(prefix.length());
        sendJson(ex, 200,
                "{\"authenticated\":true,\"username\":\"" + escapeJson(USERNAME) + "\",\"messageId\":\"" + escapeJson(messageId) + "\",\"status\":\"OK\",\"authenticatedBy\":\"vrs-session\",\"seance\":\"" + s.sid + "\"}");
    }

    private static void handleInvalidate(HttpExchange ex) throws IOException {
        log(ex);
        String sid = ex.getRequestHeaders().getFirst("vrs-session");
        if (sid == null) {
            sendJson(ex, 400, "{\"error\":\"send vrs-session header\"}");
            return;
        }
        Session s = sessions.get(sid);
        if (s != null) s.authenticated = false;
        sendJson(ex, 200, "{\"invalidated\":true}");
    }

    private static void handleDebugSessions(HttpExchange ex) throws IOException {
        log(ex);
        StringBuilder sb = new StringBuilder("{\"sessions\":[");
        boolean first = true;
        for (Session s : sessions.values()) {
            if (!first) sb.append(',');
            first = false;
            sb.append("{\"sid\":\"").append(s.sid)
                    .append("\",\"authenticated\":").append(s.authenticated)
                    .append(",\"clientId\":").append(s.clientId == null ? "null" : "\"" + escapeJson(s.clientId) + "\"")
                    .append("}");
        }
        sb.append("]}");
        sendJson(ex, 200, sb.toString());
    }

    private static void handleOpenApi(HttpExchange ex) throws IOException {
        log(ex);
        String spec = "{\n" +
                "  \"openapi\": \"3.0.3\",\n" +
                "  \"info\": {\"title\": \"Mock 1C WMS Service\", \"version\": \"1.0.0\"},\n" +
                "  \"servers\": [{\"url\": \"http://mock-1c:" + PORT + "\"}],\n" +
                "  \"paths\": {\n" +
                "    \"/RPS/hs/WMSService/messagequeue/{messageId}\": {\n" +
                "      \"get\": {\n" +
                "        \"parameters\": [{\"name\":\"messageId\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"string\",\"example\":\"3421247882389737259\"}}],\n" +
                "        \"responses\": {\"200\": {\"description\": \"OK\"}, \"401\": {\"description\": \"Missing/invalid vrs-session\"}}\n" +
                "      }\n" +
                "    },\n" +
                "    \"/app/api/orders\": {\"get\": {\"responses\": {\"200\": {\"description\": \"OK\"}}}}\n" +
                "  }\n" +
                "}";
        sendJson(ex, 200, spec);
    }

    private static void handleRoot(HttpExchange ex) throws IOException {
        log(ex);
        sendHtml(ex, 200,
                "<!doctype html><html><body><h1>Mock 1C</h1>" +
                "<a href=\"/app\">Open application</a>" +
                "<a href=\"/openapi.json\">OpenAPI</a>" +
                "</body></html>");
    }

    private static Session requireSession(HttpExchange ex) throws IOException {
        String sid = ex.getRequestHeaders().getFirst("vrs-session");
        if (sid == null || sid.isBlank()) {
            ex.getResponseHeaders().set("WWW-Authenticate", "1C-vrs-session");
            sendJson(ex, 401, "{\"error\":\"missing vrs-session\"}");
            return null;
        }
        Session session = sessions.get(sid);
        if (session == null || !session.authenticated) {
            ex.getResponseHeaders().set("WWW-Authenticate", "1C-vrs-session");
            sendJson(ex, 401, "{\"error\":\"invalid or expired vrs-session\"}");
            return null;
        }
        session.lastSeen = Instant.now();
        return session;
    }

    private static String pageHtml() {
        return "<!doctype html>\n" +
                "<html><head><meta charset=\"utf-8\"><title>Mock 1C Web Client</title></head>\n" +
                "<body>\n" +
                "<h1>Mock 1C Web Client</h1>\n" +
                "<p>This page exposes both an app-local API and an API on another path of the same host.</p>\n" +
                "<ul>\n" +
                "  <li><a href=\"/app/api/orders\">/app/api/orders</a></li>\n" +
                "  <li><a href=\"/RPS/hs/WMSService/messagequeue/3421247882389737259\">/RPS/hs/WMSService/messagequeue/...</a></li>\n" +
                "  <li><a href=\"/openapi.json\">/openapi.json</a></li>\n" +
                "</ul>\n" +
                "<pre id=\"out\">Client-side requests will appear here.</pre>\n" +
                "<script>\n" +
                "Promise.all([\n" +
                " fetch('/app/api/orders').then(r => r.text().then(t => [r.status,t])),\n" +
                " fetch('/RPS/hs/WMSService/messagequeue/3421247882389737259').then(r => r.text().then(t => [r.status,t]))\n" +
                "]).then(x => document.getElementById('out').textContent = JSON.stringify(x,null,2));\n" +
                "</script>\n" +
                "</body></html>";
    }

    private static void log(HttpExchange ex) {
        String session = ex.getRequestHeaders().getFirst("vrs-session");
        String internal = ex.getRequestHeaders().getFirst("X-ZAP-Internal-1C-Auth");
        System.out.printf("%s %s %s vrs-session=%s internal=%s%n",
                Instant.now(), ex.getRequestMethod(), ex.getRequestURI(),
                session == null ? "-" : session,
                internal == null ? "-" : internal);
    }

    private static String readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static Map<String, String> parseForm(String body) {
        Map<String, String> result = new LinkedHashMap<>();
        if (body == null || body.isEmpty()) return result;
        for (String part : body.split("&")) {
            String[] kv = part.split("=", 2);
            String k = decode(kv[0]);
            String v = kv.length == 2 ? decode(kv[1]) : "";
            result.put(k, v);
        }
        return result;
    }

    private static Query parseQuery(URI uri) {
        Map<String, String> params = new LinkedHashMap<>();
        Set<String> flags = ConcurrentHashMap.newKeySet();
        String raw = uri.getRawQuery();
        if (raw != null && !raw.isEmpty()) {
            for (String part : raw.split("&")) {
                if (part.isEmpty()) continue;
                String[] kv = part.split("=", 2);
                String key = decode(kv[0]);
                if (kv.length == 1) flags.add(key);
                else params.put(key, decode(kv[1]));
            }
        }
        return new Query(params, flags);
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static boolean isUuid(String value) {
        if (value == null) return false;
        try {
            UUID.fromString(value);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static void methodNotAllowed(HttpExchange ex, String allow) throws IOException {
        ex.getResponseHeaders().set("Allow", allow);
        sendText(ex, 405, "Method not allowed\n");
    }

    private static void sendHtml(HttpExchange ex, int status, String body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        send(ex, status, body);
    }

    private static void sendJson(HttpExchange ex, int status, String body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        send(ex, status, body);
    }

    private static void sendText(HttpExchange ex, int status, String body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
        send(ex, status, body);
    }

    private static void send(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static final class Query {
        final Map<String, String> params;
        final Set<String> flags;

        Query(Map<String, String> params, Set<String> flags) {
            this.params = params;
            this.flags = flags;
        }
    }

    private static final class Session {
        final String sid;
        volatile boolean authenticated;
        volatile String clientId;
        volatile Instant lastSeen = Instant.now();

        Session(String sid) {
            this.sid = sid;
        }
    }
}
