package com.phishguard.analyzer;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import com.google.common.net.InternetDomainName;
import com.phishguard.database.AnalysisCache;
import com.phishguard.database.PhishingDatabase;
import com.phishguard.database.TrustedDatabase;
import com.phishguard.model.AnalysisResult;


public class URLAnalyzer {
    private final PhishingDatabase database = new PhishingDatabase();
    private final TrustedDatabase trustedDatabase = new TrustedDatabase();
    private final AnalysisCache cache = new AnalysisCache();
    private static final long CACHE_TTL_HOURS = 24;
    private static final int IP_RISK = 2;
    private static final int HTTP_RISK = 1;
    private static final int LONG_URL_RISK = 1;
    private static final int AT_SYMBOL_RISK = 2;
    private static final int KEYWORD_RISK = 1;
    private static final int SUBDOMAIN_RISK = 1;
    private static final int ENCODED_RISK = 1;
    private static final int SPECIAL_CHARACTER_RISK = 1;
    private static final int MISLEADING_DOMAIN_RISK = 2;
    private static final int HYPHEN_RISK = 1;
    private static final int DATABASE_MATCH_RISK = 5;
    public boolean isKnownPhishingURL(String url) {
    return database.contains(url);
    }
    public boolean isTrustedURL(String url) {
    
        return trustedDatabase.contains(url);
   }
    public String getInvalidURLReason(String url) {

    if (url == null || url.isBlank()) {
        return "URL is empty.";
    }

    try {
        URI uri = URI.create(url);

        String scheme = uri.getScheme();
        String host = uri.getHost();

        if (scheme == null) {
            return "URL is missing a protocol. Use http:// or https://.";
        }

        if (!"http".equalsIgnoreCase(scheme)
                && !"https".equalsIgnoreCase(scheme)) {
            return "Unsupported protocol. Only HTTP and HTTPS are allowed.";
        }

        if (host == null) {
            return "URL does not contain a valid host/domain.";
        }

        if (!usesIPAddress(url)) {
            InternetDomainName domain = InternetDomainName.from(host);

            if (!domain.hasPublicSuffix()) {
                return "Domain does not have a valid public suffix.";
            }
        }

        return null;

    } catch (IllegalArgumentException e) {
        return "URL format is invalid.";
    }
}
    public boolean usesIPAddress(String url) {
        

    URI uri;

    try {
        uri = URI.create(url);
    } catch (IllegalArgumentException e) {
        return false;
    }

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
    URI uri = URI.create(url);

    String host = uri.getHost();
    String path = uri.getPath();

    String textToCheck = "";

    if (host != null) {
        textToCheck += host.toLowerCase();
    }

    if (path != null) {
        textToCheck += path.toLowerCase();
    }

    return textToCheck.contains("login")
            || textToCheck.contains("verify")
            || textToCheck.contains("account")
            || textToCheck.contains("update")
            || textToCheck.contains("secure")
            || textToCheck.contains("banking");
   }

  public String getRiskLevel(int score) {

    if (score >= 4) {
        return "High Risk";
    } else if (score >= 2) {
        return "Medium Risk";
    } else {
        return "Low Risk";
    }
}
public boolean hasManySubdomains(String url) {
    URI uri = URI.create(url);
    String host = uri.getHost();

    if (host == null) {
        return false;
    }

    if (usesIPAddress(url)) {
        return false;
    }

    String[] parts = host.split("\\.");

    return parts.length > 3;
}
  public boolean containsEncodedCharacters(String url) {

    return url.matches(".*%[0-9a-fA-F]{2}.*");
}
   private boolean containsPunycode(String url) {

    try {

        java.net.URI uri =
                java.net.URI.create(url);

        String host = uri.getHost();

        return host != null &&
               host.toLowerCase().contains("xn--");

    } catch (Exception e) {

        return false;
    }
  }
  public boolean containsSuspiciousCharacters(String url) {

    return url.contains("!")
            || url.contains("$")
            || url.contains("^")
            || url.contains("*");
}
  public String getMainDomain(String url) {

    URI uri = URI.create(url);
    String host = uri.getHost();

    if (host == null) {
        return null;
    }
    if (usesIPAddress(url)) {
    return host;
    }

    InternetDomainName domain = InternetDomainName.from(host);

    if (!domain.hasPublicSuffix()) {
        return null;
    }

    return domain.topPrivateDomain().toString();
}
  public boolean hasMisleadingDomain(String url) {

    URI uri = URI.create(url);
    String host = uri.getHost();

    if (host == null) {
        return false;
    }

    String mainDomain = getMainDomain(url);

    if (mainDomain == null) {
        return false;
    }

    String subdomainPart = host.substring(
            0,
            host.length() - mainDomain.length()
    );

    String lowerSubdomain = subdomainPart.toLowerCase();

    return lowerSubdomain.contains("google")
            || lowerSubdomain.contains("microsoft")
            || lowerSubdomain.contains("amazon")
            || lowerSubdomain.contains("paypal")
            || lowerSubdomain.contains("apple")
            || lowerSubdomain.contains("facebook");
  }
    public boolean hasManyHyphens(String url) {

    String mainDomain = getMainDomain(url);

    if (mainDomain == null) {
        return false;
    }

    int hyphenCount = 0;

    for (char ch : mainDomain.toCharArray()) {

        if (ch == '-') {
            hyphenCount++;
        }
    }

    return hyphenCount >= 2;
  }
    public boolean isCached(String url) {
    return cache.isFresh(url, CACHE_TTL_HOURS);
   }
    public AnalysisResult analyze(String url) {
        if (!isValidURL(url)) {
            return new AnalysisResult(
            0,
            "Invalid URL",
            List.of("Invalid or unsupported URL")
    );
}
    if (cache.isFresh(url, CACHE_TTL_HOURS)) {

    AnalysisResult cachedResult = cache.get(url);

    return new AnalysisResult(
            cachedResult.getRiskScore(),
            cachedResult.getRiskLevel(),
            cachedResult.getIndicators(),
            cachedResult.getAnalyzedAt(),
            isTrustedURL(url)
      );
   }
    int score = 0;
    List<String> indicators = new ArrayList<>();
    if (isKnownPhishingURL(url)) {
    score += 5;
    indicators.add("URL found in known phishing database");
   }

    if (usesIPAddress(url)){
        score += 2;
        indicators.add("URL uses a direct IP address");
    }

    URI uri = URI.create(url);
    String scheme = uri.getScheme();

    if ("http".equalsIgnoreCase(scheme)) {
        score += 1;
        indicators.add("URL uses HTTP instead of HTTPS");
    }

    if (isLongURL(url)) {
        score += 1;
        indicators.add("URL is unusually long");
    }

    if (containsAtSymbol(url)) {
        score += 2;
        indicators.add("URL contains @ symbol");
    }

    if (hasManySubdomains(url)) {
        score += 1;
        indicators.add("URL contains many subdomains");
    }

    if (containsEncodedCharacters(url)) {
        score += 1;
        indicators.add("URL contains encoded characters");
    }

    if (containsSuspiciousKeyword(url)) {
    score += 1;
    indicators.add("Suspicious keyword detected: " + getSuspiciousKeyword(url));
    }

    if (hasMisleadingDomain(url)) {
        score += 2;
        indicators.add("Possible misleading brand name in subdomain");
    }

    if (hasManyHyphens(url)) {
        score += 1;
        indicators.add("Registered domain contains multiple hyphens");
    }
    if (containsPunycode(url)) {
    score += 2;
    indicators.add("URL uses Punycode encoding");
  }
        String riskLevel = getRiskLevel(score);

        boolean trusted = isTrustedURL(url);

        AnalysisResult result = new AnalysisResult(
                score,
                riskLevel,
                indicators,
                java.time.LocalDateTime.now(),
                trusted
        );

        cache.save(url, result);

        return result;
        
    }
   public String getSuspiciousKeyword(String url) {
    URI uri;

    try {
        uri = URI.create(url);
    } catch (IllegalArgumentException e) {
        return null;
    }

    String host = uri.getHost();
    String path = uri.getPath();

    String textToCheck = "";

    if (host != null) {
        textToCheck += host.toLowerCase();
    }

    if (path != null) {
        textToCheck += path.toLowerCase();
    }

    String[] keywords = {
        "login",
        "verify",
        "account",
        "update",
        "secure",
        "banking"
    };

    for (String keyword : keywords) {
        if (textToCheck.contains(keyword)) {
            return keyword;
        }
    }

    return null;
  }
 public boolean isValidURL(String url) {
    try {
        URI uri = URI.create(url);

        String scheme = uri.getScheme();
        String host = uri.getHost();

        if (!("http".equalsIgnoreCase(scheme)
                || "https".equalsIgnoreCase(scheme))) {
            return false;
        }

        if (host == null) {
            return false;
        }

        if (usesIPAddress(url)) {
            return true;
        }

        InternetDomainName domain = InternetDomainName.from(host);

        return domain.hasPublicSuffix();

    } catch (IllegalArgumentException e) {
        return false;
    }
}

}