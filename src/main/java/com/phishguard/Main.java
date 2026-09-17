package com.phishguard;

import java.util.Scanner;

import com.phishguard.analyzer.URLAnalyzer;
import com.phishguard.model.AnalysisResult;

public class Main {
    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter a URL: ");
        String url = scanner.nextLine().trim();
        URLAnalyzer analyzer = new URLAnalyzer();

      System.out.println("You entered: " + url);

        if (!analyzer.isValidURL(url)) {
        System.out.println("Invalid URL");
        System.out.println("Reason: " + analyzer.getInvalidURLReason(url));
        scanner.close();
        return;
      }

      System.out.println("Main Domain: " + analyzer.getMainDomain(url));
      
      boolean previouslyAnalyzed = analyzer.isCached(url);
      AnalysisResult result = analyzer.analyze(url);
      if (previouslyAnalyzed) {
      System.out.println("Result retrieved from previous analysis.");
}
       System.out.println("Risk Score: " + result.getRiskScore());
        System.out.println("Risk Level: " + result.getRiskLevel());

        System.out.println("Indicators:");

        for (String indicator : result.getIndicators()) {
            System.out.println("- " + indicator);
        }
        System.out.println();
        System.out.println("Note: PhishGuard uses heuristic URL analysis.");
        System.out.println("Risk levels are based on detected indicators and do not guarantee that a URL is safe or malicious.");

        

        scanner.close();
    }
}