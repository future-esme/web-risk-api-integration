package org.example;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;

class SearchUriTest {
    private static final String THREAT_MALWARE_URL = "http://testsafebrowsing.appspot.com/s/malware.html";
    private static final String SAFE_URL = "http://testsafebrowsing.appspot.com/s/malware.html";

    @Test
    void checkWebRiskApiConnection() {
        assertDoesNotThrow(() -> {
            SearchUri searchUri = new SearchUri();
            searchUri.isSafeUriSearch(SAFE_URL, ThreatType.MALWARE);
        });
    }

    @Test
    void assertMalwareUrlIsNotSafe() {
        assertDoesNotThrow(() -> {
            SearchUri searchUri = new SearchUri();
            assertFalse(searchUri.isSafeUriSearch(THREAT_MALWARE_URL, ThreatType.MALWARE));
        });
    }
}
