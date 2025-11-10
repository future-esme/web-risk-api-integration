package org.example;

import org.example.model.ThreatType;
import org.example.model.UrlSafetyStatus;

import java.io.IOException;

public class CheckUrlSafety {
    private final SearchUri searchUri;
    public CheckUrlSafety() {
        this.searchUri = new SearchUri();
    }
    public UrlSafetyStatus checkAndGetUrlSafetyStatus(String urlToCheck) throws IOException {
        UrlSafetyStatus isSafeUrl = UrlSafetyStatus.SAFE;
        var isSafeUrlApi = searchUri.isSafeUriSearch(urlToCheck, ThreatType.MALWARE);
        if (!isSafeUrlApi) {
            isSafeUrl = UrlSafetyStatus.MALICIOUS;
        }
        return isSafeUrl;
    }
}
