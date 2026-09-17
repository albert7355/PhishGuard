package com.phishguard.analyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

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
}