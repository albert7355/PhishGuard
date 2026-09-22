package com.phishguard.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.phishguard.model.AnalysisResult;

public class URLAnalyzerTest {

    @Test
    void shouldDetectIPAddress() {
        URLAnalyzer analyzer = new URLAnalyzer();

        assertTrue(
                analyzer.usesIPAddress("http://142.250.195.14/login")
        );
    }

    @Test
    void shouldAcceptValidURL() {
        URLAnalyzer analyzer = new URLAnalyzer();

        assertTrue(
                analyzer.isValidURL("https://example.com/login")
        );
    }

    @Test
    void shouldRejectInvalidURL() {
        URLAnalyzer analyzer = new URLAnalyzer();

        assertFalse(
                analyzer.isValidURL("hello")
        );
    }

    @Test
    void shouldAddRiskForIPAddress() {
        URLAnalyzer analyzer = new URLAnalyzer();

        var result = analyzer.analyze(
                "https://192.168.1.10/login"
        );

        assertTrue(result.getRiskScore() >= 2);
    }

    @Test
    void shouldAddRiskForHTTP() {
        URLAnalyzer analyzer = new URLAnalyzer();

        var result = analyzer.analyze(
                "http://example.com"
        );

        assertTrue(result.getRiskScore() >= 1);
    }

    @Test
    void shouldAddRiskForAtSymbol() {
        URLAnalyzer analyzer = new URLAnalyzer();

        var result = analyzer.analyze(
                "https://google.com@evil-example.com"
        );

        assertTrue(result.getRiskScore() >= 2);
    }

    @Test
    void shouldAddRiskForSuspiciousKeyword() {
        URLAnalyzer analyzer = new URLAnalyzer();

        var result = analyzer.analyze(
                "https://example.com/login"
        );

        assertTrue(result.getRiskScore() >= 1);
    }

    @Test
    void shouldAddRiskForLongURL() {
        URLAnalyzer analyzer = new URLAnalyzer();

        var result = analyzer.analyze(
                "https://example.com/this-is-a-very-long-url-that-contains-many-characters-for-testing"
        );

        assertTrue(result.getRiskScore() >= 1);
    }

    @Test
    void shouldCombineMultipleRiskIndicators() {
        URLAnalyzer analyzer = new URLAnalyzer();

        var result = analyzer.analyze(
                "https://google.com@evil-example.com/login"
        );

        assertTrue(result.getRiskScore() >= 3);
    }

    @Test
    void shouldAddRiskForManySubdomains() {
        URLAnalyzer analyzer = new URLAnalyzer();

        var result = analyzer.analyze(
                "https://secure.login.example.com"
        );

        assertTrue(result.getRiskScore() >= 1);
    }

    @Test
    void shouldAddRiskForEncodedCharacters() {
        URLAnalyzer analyzer = new URLAnalyzer();

        var result = analyzer.analyze(
                "https://example.com/%6C%6F%67%69%6E"
        );

        assertTrue(result.getRiskScore() >= 1);
    }

    @Test
    void shouldDetectSuspiciousCharacters() {
        URLAnalyzer analyzer = new URLAnalyzer();

        assertTrue(
                analyzer.containsSuspiciousCharacters(
                        "https://example.com/login!$"
                )
        );
    }

    @Test
    void shouldAddRiskForMisleadingBrandName() {
        URLAnalyzer analyzer = new URLAnalyzer();

        var result = analyzer.analyze(
                "https://google.com.security-check.example.com/login"
        );

        assertTrue(result.getRiskScore() >= 4);
    }

    @Test
    void shouldAddRiskForMultipleHyphens() {
        URLAnalyzer analyzer = new URLAnalyzer();

        var result = analyzer.analyze(
                "https://secure-login-account-example.com"
        );

        assertTrue(result.getRiskScore() >= 1);
    }

    @Test
    void shouldDetectKnownPhishingURL() {
        URLAnalyzer analyzer = new URLAnalyzer();

        assertTrue(
                analyzer.isKnownPhishingURL(
                        "http://142.250.195.14/login"
                )
        );
    }

    @Test
    void shouldReturnLowRisk() {
        URLAnalyzer analyzer = new URLAnalyzer();

        assertEquals(
                "Low Risk",
                analyzer.getRiskLevel(0)
        );
    }

    @Test
    void shouldReturnMediumRisk() {
        URLAnalyzer analyzer = new URLAnalyzer();

        assertEquals(
                "Medium Risk",
                analyzer.getRiskLevel(2)
        );
    }

    @Test
    void shouldReturnHighRisk() {
        URLAnalyzer analyzer = new URLAnalyzer();

        assertEquals(
                "High Risk",
                analyzer.getRiskLevel(4)
        );
    }

    @Test
    void shouldExtractMainDomain() {
        URLAnalyzer analyzer = new URLAnalyzer();

        assertEquals(
                "example.com",
                analyzer.getMainDomain(
                        "https://secure.login.example.com"
                )
        );
    }

    @Test
    void shouldExplainInvalidURL() {
        URLAnalyzer analyzer = new URLAnalyzer();

        String reason = analyzer.getInvalidURLReason("hello");

        assertNotNull(reason);

        assertTrue(
                reason.contains("protocol")
        );
    }

    @Test
    void shouldCacheURLAfterAnalysis() {
        URLAnalyzer analyzer = new URLAnalyzer();

        String url = "https://cache-test-one.example.com";

        analyzer.analyze(url);

        assertTrue(
                analyzer.isCached(url)
        );
    }

    @Test
    void shouldRetrieveCachedResult() {
        URLAnalyzer analyzer = new URLAnalyzer();

        String url = "https://cache-test-two.example.com";

        var firstResult = analyzer.analyze(url);
        var secondResult = analyzer.analyze(url);

        assertEquals(
                firstResult.getRiskScore(),
                secondResult.getRiskScore()
        );
    }

    @Test
    void shouldRecognizeFreshCache() {
        URLAnalyzer analyzer = new URLAnalyzer();

        String url = "https://cache-test-three.example.com";

        analyzer.analyze(url);

        assertTrue(
                analyzer.isCached(url)
        );
    }

    @Test
    void shouldPreserveCachedRiskLevel() {
        URLAnalyzer analyzer = new URLAnalyzer();

        String url = "https://cache-test-four.example.com";

        var firstResult = analyzer.analyze(url);
        var secondResult = analyzer.analyze(url);

        assertEquals(
                firstResult.getRiskLevel(),
                secondResult.getRiskLevel()
        );
    }

    @Test
    void shouldCacheDifferentURLsSeparately() {
        URLAnalyzer analyzer = new URLAnalyzer();

        String firstURL = "https://cache-test-five.example.com";
        String secondURL = "https://cache-test-six.example.com";

        var firstResult = analyzer.analyze(firstURL);
        var secondResult = analyzer.analyze(secondURL);

        assertTrue(analyzer.isCached(firstURL));
        assertTrue(analyzer.isCached(secondURL));

        assertNotNull(firstResult);
        assertNotNull(secondResult);
    }

    @Test
    void shouldDetectTrustedURL() {
        URLAnalyzer analyzer = new URLAnalyzer();

        assertTrue(
                analyzer.isTrustedURL("https://example.com")
        );
    }

   @Test
     void shouldMarkTrustedURLInAnalysisResult() {

    URLAnalyzer analyzer = new URLAnalyzer();

    var result = analyzer.analyze(
            "https://trusted-test.example.com"
    );

    assertTrue(
            result.isTrusted()
    );
}

    @Test
    void shouldNotMarkUnknownURLAsTrusted() {
        URLAnalyzer analyzer = new URLAnalyzer();

        var result = analyzer.analyze(
                "https://unknown-test-domain.example"
        );

        assertFalse(
                result.isTrusted()
        );
    }
    @Test
        void shouldDetectNewTrustedURL() {

            URLAnalyzer analyzer = new URLAnalyzer();

            assertTrue(
                    analyzer.isTrustedURL("https://trusted-test.example.com")
            );
        }
        @Test
void shouldDetectPunycode() {

    URLAnalyzer analyzer = new URLAnalyzer();

    AnalysisResult result =
            analyzer.analyze("https://xn--pple-43d.com/login");

    assertTrue(
            result.getIndicators()
                    .contains("URL uses Punycode encoding")
    );
}
@Test
void shouldNotMarkLegitimateURLsAsHighRisk() {

    URLAnalyzer analyzer = new URLAnalyzer();

    String[] legitimateUrls = {
            "https://example.com",
            "https://www.google.com",
            "https://www.microsoft.com",
            "https://www.apple.com",
            "https://www.amazon.com",
            "https://github.com",
            "https://leetcode.com",
            "https://stackoverflow.com"
    };

    for (String url : legitimateUrls) {

        AnalysisResult result = analyzer.analyze(url);

        assertNotEquals(
                "High Risk",
                result.getRiskLevel(),
                "Legitimate URL incorrectly marked High Risk: " + url
        );
    }
}
@Test
void shouldHandleSuspiciousLookingURLsWithoutAssumingPhishing() {

    URLAnalyzer analyzer = new URLAnalyzer();

    String[] suspiciousLookingUrls = {
            "http://example.com/login",
            "https://secure.example.com/account/login",
            "https://example.com/account/verify?session=12345",
            "https://login.example.com/user/account"
    };

    for (String url : suspiciousLookingUrls) {

        AnalysisResult result = analyzer.analyze(url);

        assertNotEquals(
                "High Risk",
                result.getRiskLevel(),
                "URL was automatically classified as High Risk: " + url
        );
    }
}
@Test
void shouldDetectMultipleRiskIndicators() {

    URLAnalyzer analyzer = new URLAnalyzer();

    AnalysisResult result =
            analyzer.analyze("http://142.250.195.14/login");

    assertTrue(result.getRiskScore() >= 4);

    assertTrue(
            result.getIndicators()
                    .contains("URL uses a direct IP address")
    );

    assertTrue(
            result.getIndicators()
                    .contains("URL uses HTTP instead of HTTPS")
    );

    assertTrue(
            result.getIndicators()
                    .contains("Suspicious keyword detected: login")
    );
}
@Test
void shouldAddRiskForPunycode() {

    URLAnalyzer analyzer = new URLAnalyzer();

    AnalysisResult result =
            analyzer.analyze("https://xn--pple-43d.com/login");

    assertTrue(result.getRiskScore() >= 3);

    assertTrue(
            result.getIndicators()
                    .contains("URL uses Punycode encoding")
    );
 }
 @Test
void shouldExplainEmptyURL() {

    URLAnalyzer analyzer = new URLAnalyzer();

    assertEquals(
            "URL is empty.",
            analyzer.getInvalidURLReason("")
    );
}
@Test
void shouldExplainMissingProtocol() {

    URLAnalyzer analyzer = new URLAnalyzer();

    assertEquals(
            "URL is missing a protocol. Use http:// or https://.",
            analyzer.getInvalidURLReason("example.com")
    );
}
@Test
void shouldExplainUnsupportedProtocol() {

    URLAnalyzer analyzer = new URLAnalyzer();

    assertEquals(
            "Unsupported protocol. Only HTTP and HTTPS are allowed.",
            analyzer.getInvalidURLReason("ftp://example.com")
    );
}
}