package org.example;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class SearchUri {
    public static final String WEB_RISK_URI_KEY = "WEB_RISK_URI";
    public static final String WEB_RISK_URI_DEFAULT_URL = "https://webrisk.googleapis.com/v1/uris:search";
    public static final String API_KEY_KEY = "API_KEY";
    public static final String API_KEY_DEFAULT_KEY = "123456";
    public final String webRiskString;
    public final String apiKey;
    private static final String REQUEST_QUERY_PARAMS = "?uri=%s&threatTypes=%s";

    public SearchUri() {
        this.webRiskString = PropertyUtil.getProperty(WEB_RISK_URI_KEY, WEB_RISK_URI_DEFAULT_URL);
        this.apiKey = PropertyUtil.getProperty(API_KEY_KEY, API_KEY_DEFAULT_KEY);
    }

    // This method is used to check whether a URI is on a given threatList. Multiple threatLists may
    // be searched in a single query.
    // The response will list all requested threatLists the URI was found to match. If the URI is not
    // found on any of the requested ThreatList an empty response will be returned.
    public boolean isSafeUriSearch(String uri, ThreatType threatType) throws IOException {
        HttpURLConnection conn = getHttpURLConnection(uri, threatType);

        int status = conn.getResponseCode();
        InputStream responseStream = (status < 400) ? conn.getInputStream() : conn.getErrorStream();

        StringBuilder response = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(responseStream, StandardCharsets.UTF_8))) {
            String responseLine;
            while ((responseLine = br.readLine()) != null) {
                response.append(responseLine.trim());
            }
        }

        conn.disconnect();

        return !response.toString().contains("\"threat\"");
    }

    private HttpURLConnection getHttpURLConnection(String uri, ThreatType threatType) throws IOException {
        String queryParams = String.format(
                REQUEST_QUERY_PARAMS,
                uri, threatType
        );
        URL webRiskUrl = URI.create(webRiskString + queryParams).toURL();
        HttpURLConnection conn = (HttpURLConnection) webRiskUrl.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        conn.setRequestProperty("X-goog-api-key", apiKey);
        conn.setDoOutput(true);

        return conn;
    }

    private static class PropertyUtil {
        public static String getProperty(String key, String defaultValue) {
            String environmentVariableValue = System.getenv(key);
            return environmentVariableValue != null ? environmentVariableValue : defaultValue;
        }
    }
}