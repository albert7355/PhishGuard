# PhishGuard

A beginner-friendly cybersecurity tool for detecting suspicious URLs using rule-based phishing indicators and risk scoring.

## Overview

PhishGuard analyzes a submitted URL without visiting or opening it.

It examines the URL structure for potentially suspicious characteristics, assigns risk points to detected indicators, and produces a risk classification.

PhishGuard is designed as an educational cybersecurity project to demonstrate how explainable, rule-based URL analysis can be implemented.

> **Important:** PhishGuard does not guarantee that a URL is safe or malicious. A risk score represents detected indicators and should not be treated as a definitive security verdict.

---

## Features

- URL validation
- Rule-based phishing detection
- Risk scoring system
- Risk classification
- Direct IP address detection
- HTTP vs HTTPS detection
- Suspicious keyword detection
- Suspicious URL character detection
- `@` symbol detection
- URL encoding detection
- Long URL detection
- Multiple subdomain detection
- Misleading brand-name detection in subdomains
- Multiple-hyphen detection
- Punycode (`xn--`) detection
- Local phishing URL test database
- Local trusted URL database
- Analysis result caching
- Cache expiration using TTL
- Web-based dashboard
- REST API
- Recent analysis history
- Automated JUnit testing

---

## How It Works

PhishGuard follows this basic flow:

```text
User submits URL
       |
       v
URL Validation
       |
       v
URL Structure Analysis
       |
       v
Detection Rules
       |
       v
Risk Score Calculation
       |
       v
Risk Classification
       |
       v
Analysis Result
```
