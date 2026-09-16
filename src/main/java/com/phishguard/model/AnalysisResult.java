package com.phishguard.model;

import java.util.List;

public class AnalysisResult {

    private int riskScore;
    private String riskLevel;
    private List<String> indicators;

    public AnalysisResult(int riskScore, String riskLevel, List<String> indicators) {
        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.indicators = indicators;
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
}