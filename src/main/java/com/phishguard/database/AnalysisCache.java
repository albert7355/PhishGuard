package com.phishguard.database;

import java.util.HashMap;
import java.util.Map;

import com.phishguard.model.AnalysisResult;

public class AnalysisCache {

    private final Map<String, AnalysisResult> cache = new HashMap<>();

    public void save(String url, AnalysisResult result) {
        cache.put(normalize(url), result);
    }

    public AnalysisResult get(String url) {
        return cache.get(normalize(url));
    }

    private String normalize(String url) {
        String normalizedUrl = url.trim().toLowerCase();

        if (normalizedUrl.endsWith("/")) {
            normalizedUrl = normalizedUrl.substring(0, normalizedUrl.length() - 1);
        }

        return normalizedUrl;
    }
}