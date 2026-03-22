# DevSecOps & AI Risk Pipeline

This document outlines the end-to-end security automation and AI-driven risk scoring pipeline implemented in OWASP Juice Shop.

## 1. Architecture Overview

The pipeline integrates automated security scanning, centralized vulnerability management, and AI data processing to provide a prioritized view of security risks.

### Flow Diagram
1. **Push/PR** → Triggers GitHub Actions.
2. **Scanning** → Parallel execution of SAST, SCA, and DAST.
3. **Consolidation** → Results uploaded to **DefectDojo**.
4. **Enrichment** → Findings patched with **EPSS** scores (Exploit Prediction).
5. **AI Extraction** → Data collected and transformed into a feature matrix.
6. **Risk Scoring** → Synthetic AI Risk Score generated for prioritization.

---

## 2. Security Scanning Phase

The pipeline employs a defense-in-depth scanning strategy:

| Category | Tool | Scope |
| :--- | :--- | :--- |
| **SAST** | Semgrep | Static analysis of source code patterns. |
| **SCA** | Trivy | Vulnerability scanning of filesystem and Docker images. |
| **SCA** | Dependency-Check | Detailed analysis of third-party library vulnerabilities. |
| **DAST** | OWASP ZAP | Dynamic testing of the running application container. |

---

## 3. Vulnerability Management (DefectDojo)

Results are managed via the `.github/scripts/` toolset:
- **`defectdojo-upload.sh`**: Uses the `reimport-scan` API. It maps scan filenames to `test_title` to maintain stable history across different scanners.
- **`defectdojo-epss-patch.py`**: A post-upload script that queries FIRST.org for EPSS scores and directly updates DefectDojo findings.

---

## 4. AI Data Pipeline (`ai/`)

The AI pipeline prepares data for machine learning models:

### `collector.py`
Fetches findings from DefectDojo and enriches them with EPSS data.
- **Optimization**: Prioritizes EPSS scores already present in DefectDojo, only querying the FIRST.org API for missing CVEs.

### `feature_engineering.py`
Transforms raw findings into a feature matrix (`features.csv`).
- **Scanner Mapping**: Categories findings by source (SAST, DAST, SCA).
- **CWE Categorization**: Maps CWE IDs to risk areas (e.g., Injection, Auth).
- **Synthetic AI Risk Score**: A weighted calculation (1–10) based on:
    - **40%** CVSS Score (Base severity)
    - **30%** EPSS Score (Exploit probability)
    - **20%** Severity Label (DefectDojo normalization)
    - **10%** Freshness (Finding age)

---

## 5. Pipeline Reliability

To ensure data integrity, the **AI Data Pipeline** job in `.github/workflows/devsecops-pipeline.yml` includes a **30-second processing delay**. This allows DefectDojo to finalize background asynchronous tasks (deduplication, normalization) before the data is extracted for AI processing.
