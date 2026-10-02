# Phishing Investigation SOC Lab

A Python-based SOC automation project for investigating suspicious phishing emails and generating a structured security investigation report.

## Features

- Email and header analysis
- SPF, DKIM and DMARC analysis
- URL, domain, IP and email IOC extraction
- File attachment hash analysis
- VirusTotal threat intelligence
- urlscan.io analysis
- Evidence correlation
- Risk scoring and severity classification
- Automated HTML investigation report
- osTicket incident ticket creation

## Architecture

```text
Phishing Email
      ↓
Email Parser
      ↓
Header & Authentication Analysis
      ↓
IOC & Attachment Extraction
      ↓
VirusTotal + urlscan.io
      ↓
Evidence Correlation
      ↓
Risk Scoring
      ↓
SOC Investigation Report
      ↓
osTicket Incident
