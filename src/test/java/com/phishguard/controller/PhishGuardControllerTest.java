package com.phishguard.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import com.phishguard.model.AnalysisResult;

public class PhishGuardControllerTest {

    private final PhishGuardController controller =
            new PhishGuardController();

    @Test
    void shouldAnalyzeValidURL() {

        ResponseEntity<?> response =
                controller.analyzeURL("https://example.com");

        assertEquals(
                200,
                response.getStatusCode().value()
        );

        assertNotNull(response.getBody());
    }

    @Test
    void shouldRejectInvalidURL() {

        ResponseEntity<?> response =
                controller.analyzeURL("example.com");

        assertEquals(
                400,
                response.getStatusCode().value()
        );

        assertNotNull(response.getBody());
    }

    @Test
    void shouldReturnAnalysisResultForValidURL() {

        ResponseEntity<?> response =
                controller.analyzeURL("https://example.com");

        assertTrue(
                response.getBody() instanceof AnalysisResult
        );

        AnalysisResult result =
                (AnalysisResult) response.getBody();

        assertEquals(
                0,
                result.getRiskScore()
        );

        assertEquals(
                "Low Risk",
                result.getRiskLevel()
        );

        assertTrue(
                result.isTrusted()
        );
    }

    @Test
    void shouldReturnErrorDetailsForInvalidURL() {

        ResponseEntity<?> response =
                controller.analyzeURL("example.com");

        assertTrue(
                response.getBody() instanceof Map
        );

        Map<?, ?> body =
                (Map<?, ?>) response.getBody();

        assertEquals(
                false,
                body.get("valid")
        );

        assertNotNull(
                body.get("message")
        );
    }
    @Test
void shouldReturnHighRiskResultForKnownPhishingURL() {

    ResponseEntity<?> response =
            controller.analyzeURL(
                    "http://142.250.195.14/login"
            );

    assertEquals(
            200,
            response.getStatusCode().value()
    );

    assertTrue(
            response.getBody() instanceof AnalysisResult
    );

    AnalysisResult result =
            (AnalysisResult) response.getBody();

    assertEquals(
            "High Risk",
            result.getRiskLevel()
    );

    assertEquals(
            9,
            result.getRiskScore()
    );

    assertTrue(
            result.getIndicators().size() >= 3
    );
}
}