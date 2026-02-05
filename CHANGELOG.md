# Changelog

All notable changes to the B-Hunters project will be documented in this file.

## [2.0.0] - 2024-02-04

### 🚀 Added

#### Testing Pipeline
- **pytest framework** with comprehensive test configuration
- **GitHub Actions CI/CD** workflow for automated testing
- **Unit tests** for core components (`bhunter.py`, `cli.py`)
- **Integration tests** for Karton service chains
- **Coverage reporting** with 80%+ target threshold
- **Code quality tools**: flake8, black, isort, mypy
- **Development dependencies** in `requirements-dev.txt`

#### Enhanced Reporting
- **New reporting module** (`b_hunters/reports/`)
  - Risk scoring engine with severity classification
  - Support for JSON, HTML, and PDF output formats
  - Executive summary generation
  - Comparative report support (before/after scanning)
- **Risk Scoring System**
  - 5-tier severity classification (Critical, High, Medium, Low, Info)
  - Risk score calculation (0-10 scale)
  - CWE and vulnerability type mapping
- **Third-Party Integrations**
  - Jira issue export
  - GitLab Security Dashboard format
  - SARIF (Static Analysis Results Interchange Format)
  - DefectDojo import format
  - CSV export for spreadsheets

#### CLI Enhancements
- **New commands:**
  - `enhanced-report`: Generate reports with risk analysis
  - `export`: Export findings to external tools
- **Extended report formats:** html, json, pdf, executive, csv
- **Export formats:** jira, gitlab, sarif, defectdojo

### 📦 Dependencies
- Added testing: pytest, pytest-cov, pytest-asyncio, pytest-mock
- Added mocking: responses, mongomock, moto, freezegun
- Added reporting: weasyprint, jinja2, markdown
- Added quality: flake8, black, isort, mypy

### 🔧 Infrastructure
- Configured pytest with coverage thresholds
- Added multi-version Python testing (3.8-3.12)
- Integrated with Codecov for coverage tracking

## [1.0.0] - 2024-01-01

### Initial Release
- Core B-Hunters framework
- Karton-based microservices architecture
- CLI with scan and report commands
- Multiple security tool integrations
- MongoDB and S3 integration

---

[2.0.0]: https://github.com/B-Hunters/B-Hunters/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/B-Hunters/B-Hunters/releases/tag/v1.0.0
