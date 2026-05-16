package ru.mirea.phishing;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Встроенный HTTP-сервер на JDK для demo Web UI.
 * <p>
 * GET  /          → HTML-страница с формой
 * POST /api/predict → JSON {"url": "..."} → JSON с результатом
 */
public final class WebServer {

    private static final Logger log = LoggerFactory.getLogger(WebServer.class);

    private final PredictionService predictor;
    private final int port;
    private HttpServer server;

    public WebServer(PredictionService predictor, int port) {
        this.predictor = predictor;
        this.port = port;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", this::handleIndex);
        server.createContext("/api/predict", this::handlePredict);
        server.createContext("/api/info", this::handleInfo);
        server.setExecutor(null); // default executor
        server.start();
        log.info("Web UI is up at http://localhost:{}/", port);
    }

    public void stop() {
        if (server != null) server.stop(0);
    }

    private void handleIndex(HttpExchange ex) throws IOException {
        if (!ex.getRequestURI().getPath().equals("/")) {
            send(ex, 404, "text/plain; charset=utf-8", "Not Found");
            return;
        }
        String html = loadResource("web/index.html");
        send(ex, 200, "text/html; charset=utf-8", html);
    }

    private void handleInfo(HttpExchange ex) throws IOException {
        String json = String.format(java.util.Locale.ROOT,
                "{\"features\":%d,\"accuracy\":%.4f,\"mode\":\"lexical-only\"}",
                predictor.getFeatureCount(), predictor.getAccuracy());
        send(ex, 200, "application/json", json);
    }

    private void handlePredict(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, "application/json", "{\"error\":\"method_not_allowed\"}");
            return;
        }

        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String url = extractJsonField(body, "url");
        if (url == null || url.isBlank()) {
            send(ex, 400, "application/json", "{\"error\":\"url_required\"}");
            return;
        }

        try {
            PredictionService.Prediction p = predictor.predict(url);
            String json = String.format(Locale.ROOT,
                    "{\"url\":%s,\"phishing\":%b,\"probabilityPhishing\":%.4f," +
                    "\"probabilityLegitimate\":%.4f,\"features\":%s,\"ruleOverride\":%s}",
                    jsonEscape(p.url()), p.phishing(),
                    p.probabilityPhishing(), p.probabilityLegitimate(),
                    featuresToJson(p.features()),
                    p.ruleOverride() == null ? "null" : jsonEscape(p.ruleOverride()));
            send(ex, 200, "application/json", json);
        } catch (Exception e) {
            log.error("Predict failed", e);
            send(ex, 500, "application/json",
                    "{\"error\":\"internal_error\",\"message\":" + jsonEscape(e.getMessage()) + "}");
        }
    }

    private static String featuresToJson(double[] f) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < f.length && i < UrlFeatureExtractor.FEATURE_NAMES.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(UrlFeatureExtractor.FEATURE_NAMES.get(i)).append("\":")
                    .append((int) f[i]);
        }
        return sb.append("}").toString();
    }

    /** Лёгкая (но небезопасная для произвольного JSON!) выборка поля по имени. */
    private static String extractJsonField(String body, String field) {
        // Ищем "field": "value"
        String key = "\"" + field + "\"";
        int idx = body.indexOf(key);
        if (idx < 0) return null;
        int colon = body.indexOf(':', idx + key.length());
        if (colon < 0) return null;
        int i = colon + 1;
        // Пропустим пробелы
        while (i < body.length() && Character.isWhitespace(body.charAt(i))) i++;
        if (i >= body.length() || body.charAt(i) != '"') return null;
        i++;
        StringBuilder sb = new StringBuilder();
        while (i < body.length() && body.charAt(i) != '"') {
            char c = body.charAt(i);
            if (c == '\\' && i + 1 < body.length()) {
                char next = body.charAt(i + 1);
                sb.append(switch (next) {
                    case 'n' -> '\n';
                    case 't' -> '\t';
                    case '"' -> '"';
                    case '\\' -> '\\';
                    case '/' -> '/';
                    default -> next;
                });
                i += 2;
            } else {
                sb.append(c);
                i++;
            }
        }
        return sb.toString();
    }

    private static String jsonEscape(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\t' -> sb.append("\\t");
                case '\r' -> sb.append("\\r");
                default -> sb.append(c);
            }
        }
        return sb.append("\"").toString();
    }

    private static void send(HttpExchange ex, int status, String contentType, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String loadResource(String path) throws IOException {
        try (InputStream is = WebServer.class.getClassLoader().getResourceAsStream(path)) {
            if (is == null) throw new IOException("Resource not found: " + path);
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
