package com.phishguard;

import java.util.Scanner;

import com.phishguard.analyzer.URLAnalyzer;

public class Main {
    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter a URL: ");
        String url = scanner.nextLine().trim();

        System.out.println("You entered: " + url);

        URLAnalyzer analyzer = new URLAnalyzer();

        int riskScore = analyzer.calculateRiskScore(url);
        String riskLevel = analyzer.getRiskLevel(riskScore);

        System.out.println("Risk Score: " + riskScore);
        System.out.println("Risk Level: " + riskLevel);

        scanner.close();
    }
}