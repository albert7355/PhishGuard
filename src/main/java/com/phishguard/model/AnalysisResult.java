package com.phishguard.model;

import java.time.LocalDateTime;
import java.util.List;

public class AnalysisResult {

    private int riskScore;
    private String riskLevel;
    private List<String> indicators;
    private LocalDateTime analyzedAt;
    private boolean trusted;

    public AnalysisResult(
            int riskScore,
            String riskLevel,
            List<String> indicators) {

        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.indicators = indicators;
        this.analyzedAt = LocalDateTime.now();
        this.trusted = false;
    }

    public AnalysisResult(
            int riskScore,
            String riskLevel,
            List<String> indicators,
            LocalDateTime analyzedAt) {

        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.indicators = indicators;
        this.analyzedAt = analyzedAt;
        this.trusted = false;
    }

    public AnalysisResult(
            int riskScore,
            String riskLevel,
            List<String> indicators,
            LocalDateTime analyzedAt,
            boolean trusted) {

        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.indicators = indicators;
        this.analyzedAt = analyzedAt;
        this.trusted = trusted;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public List<String> getIndicators() {
        return indicators;
    }

    public LocalDateTime getAnalyzedAt() {
        return analyzedAt;
    }

    public boolean isTrusted() {
        return trusted;
    }
}