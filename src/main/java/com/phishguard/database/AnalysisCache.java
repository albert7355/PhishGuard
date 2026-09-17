package com.phishguard.database;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.phishguard.model.AnalysisResult;

public class AnalysisCache {

    private final Map<String, AnalysisResult> cache = new HashMap<>();

    private final File cacheFile = new File("phishguard_cache.txt");

    public AnalysisCache() {
        loadCache();
    }

    public void save(String url, AnalysisResult result) {

        String normalizedUrl = normalize(url);

        cache.put(normalizedUrl, result);

        try (BufferedWriter writer = new BufferedWriter(
                new FileWriter(cacheFile))) {

            for (Map.Entry<String, AnalysisResult> entry : cache.entrySet()) {

                AnalysisResult cachedResult = entry.getValue();

                writer.write(entry.getKey());
                writer.write("|");
                writer.write(String.valueOf(cachedResult.getRiskScore()));
                writer.write("|");
                writer.write(cachedResult.getRiskLevel());
                writer.write("|");
                writer.write(cachedResult.getAnalyzedAt().toString());
                writer.write("|");
                writer.write(String.valueOf(cachedResult.isTrusted()));
                writer.write("|");
                writer.write(String.join(";", cachedResult.getIndicators()));
                writer.newLine();
            }

        } catch (IOException e) {
            System.out.println("Could not save analysis to cache.");
        }
    }

    public AnalysisResult get(String url) {
        return cache.get(normalize(url));
    }

    public boolean contains(String url) {
        return cache.containsKey(normalize(url));
    }

    public boolean isFresh(String url, long ttlHours) {

        AnalysisResult result = cache.get(normalize(url));

        if (result == null) {
            return false;
        }

        LocalDateTime analyzedAt = result.getAnalyzedAt();

        long ageHours = Duration.between(
                analyzedAt,
                LocalDateTime.now()
        ).toHours();

        return ageHours < ttlHours;
    }

    private void loadCache() {

        if (!cacheFile.exists()) {
            return;
        }

        try (BufferedReader reader = new BufferedReader(
                new FileReader(cacheFile))) {

            String line;

            while ((line = reader.readLine()) != null) {

                String[] parts = line.split("\\|", 6);

                if (parts.length != 6) {
                    continue;
                }

                String url = parts[0];

                int score = Integer.parseInt(parts[1]);

                String riskLevel = parts[2];

                LocalDateTime analyzedAt =
                        LocalDateTime.parse(parts[3]);

                boolean trusted =
                        Boolean.parseBoolean(parts[4]);

                List<String> indicators = new ArrayList<>();

                if (!parts[5].isEmpty()) {

                    String[] indicatorArray =
                            parts[5].split(";");

                    for (String indicator : indicatorArray) {
                        indicators.add(indicator);
                    }
                }

                AnalysisResult result = new AnalysisResult(
                        score,
                        riskLevel,
                        indicators,
                        analyzedAt,
                        trusted
                );

                cache.put(url, result);
            }

        } catch (Exception e) {
            System.out.println("Could not load analysis cache.");
        }
    }

    private String normalize(String url) {

        String normalizedUrl = url.trim().toLowerCase();

        if (normalizedUrl.endsWith("/")) {
            normalizedUrl = normalizedUrl.substring(
                    0,
                    normalizedUrl.length() - 1
            );
        }

        return normalizedUrl;
    }
}