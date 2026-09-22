package com.phishguard.controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.phishguard.analyzer.URLAnalyzer;
import com.phishguard.model.AnalysisResult;

@RestController
public class PhishGuardController {

    private final URLAnalyzer analyzer = new URLAnalyzer();

    @GetMapping("/api/analyze")
    public ResponseEntity<?> analyzeURL(
            @RequestParam("url") String url) {

        if (!analyzer.isValidURL(url)) {

            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                            "valid", false,
                            "message",
                            analyzer.getInvalidURLReason(url)
                    ));
        }

        AnalysisResult result =
                analyzer.analyze(url);

        return ResponseEntity.ok(result);
    }
}