package com.phishguard.analyzer;

import java.net.URI;


public class URLAnalyzer {

    public boolean usesIPAddress(String url) {

    URI uri = URI.create(url);

    String host = uri.getHost();

    if (host == null) {
        return false;
    }

    String[] parts = host.split("\\.");

    if (parts.length == 4) {

        boolean allNumbers = true;

        for (String part : parts) {

            if (!part.matches("\\d+")) {
                allNumbers = false;
                break;
            }

            int number = Integer.parseInt(part);

            if (number < 0 || number > 255) {
                allNumbers = false;
                break;
            }
        }

        return allNumbers;
    }

    return false;
}
public boolean isLongURL(String url) {

    return url.length() > 75;
  }
public boolean containsAtSymbol(String url) {

    return url.contains("@");
  }
  public boolean containsSuspiciousKeyword(String url) {

    String lowerURL = url.toLowerCase();

    return lowerURL.contains("login")
            || lowerURL.contains("verify")
            || lowerURL.contains("account")
            || lowerURL.contains("update")
            || lowerURL.contains("secure")
            || lowerURL.contains("banking");
   }
   public int calculateRiskScore(String url) {

    int score = 0;

    if (usesIPAddress(url)) {
        score += 2;
    }

    URI uri = URI.create(url);
   String scheme = uri.getScheme();

    if ("http".equalsIgnoreCase(scheme)) {
      score += 1;
    }

    if (isLongURL(url)) {
        score += 1;
    }

    if (containsAtSymbol(url)) {
        score += 2;
    }

    if (containsSuspiciousKeyword(url)) {
        score += 1;
    }

    return score;
}
  public String getRiskLevel(int score) {

    if (score >= 4) {
        return "Likely Phishing";
    } else if (score >= 2) {
        return "Suspicious";
    } else {
        return "Likely Safe";
    }
}
}