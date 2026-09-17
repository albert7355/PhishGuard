package com.phishguard.database;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

public class TrustedDatabase {

    private final Set<String> trustedUrls = new HashSet<>();

    public TrustedDatabase() {
        loadDatabase();
    }

    private void loadDatabase() {

        InputStream inputStream = getClass()
                .getClassLoader()
                .getResourceAsStream("trusted_urls.txt");

        if (inputStream == null) {
            return;
        }

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {

            String line;

            while ((line = reader.readLine()) != null) {

                line = line.trim();

                if (!line.isEmpty() && !line.startsWith("#")) {
                    trustedUrls.add(normalize(line));
                }
            }

        } catch (Exception e) {
            System.out.println("Could not load trusted URL database.");
        }
    }

    public boolean contains(String url) {
        return trustedUrls.contains(normalize(url));
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