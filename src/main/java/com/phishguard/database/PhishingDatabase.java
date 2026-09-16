package com.phishguard.database;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

public class PhishingDatabase {

    private final Set<String> phishingUrls = new HashSet<>();

    public PhishingDatabase() {
        loadDatabase();
    }

    private void loadDatabase() {

        InputStream inputStream = getClass()
                .getClassLoader()
                .getResourceAsStream("phishing_urls.txt");

        if (inputStream == null) {
            return;
        }

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {

            String line;

            while ((line = reader.readLine()) != null) {

                line = line.trim();

                if (!line.isEmpty()) {
                    phishingUrls.add(line);
                }
            }

        } catch (Exception e) {
            System.out.println("Could not load phishing database.");
        }
    }

   public boolean contains(String url) {
    String normalizedUrl = url.trim().toLowerCase();

    if (normalizedUrl.endsWith("/")) {
        normalizedUrl = normalizedUrl.substring(0, normalizedUrl.length() - 1);
    }

    for (String phishingUrl : phishingUrls) {

        String storedUrl = phishingUrl.trim().toLowerCase();

        if (storedUrl.endsWith("/")) {
            storedUrl = storedUrl.substring(0, storedUrl.length() - 1);
        }

        if (storedUrl.equals(normalizedUrl)) {
            return true;
        }
    }

    return false;
}
    public static void main(String[] args) {

    PhishingDatabase database = new PhishingDatabase();

    System.out.println(
            database.contains("http://142.250.195.14/login")
    );

    System.out.println(
            database.contains("https://example.com")
    );
  }
}