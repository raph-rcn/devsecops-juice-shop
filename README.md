# DevSecOps Juice Shop

This repo wraps the vulnerable OWASP Juice Shop to practice setting up an end-to-end DevSecOps lab.

## GitHub Actions

### Juice-Shop Scanning

- Dependency vulnerability: npm audit
- Container image scanning: Trivy/Grype (on the Juice Shop image).
- DAST: OWASP ZAP baseline scan against running Juice Shop.
- SBOM: Syft (CycloneDX/SPDX) + attach as artifact.

### Pipeline Scanning

- Secrets scanning: Gitleaks (pre-commit + CI).
- SAST: Semgrep (JS/TS rules, OWASP Top 10).
- Dependency vulnerability: npm audit + Trivy (filesystem scan) or Snyk (optional).
- Dockerfile linting: Hadolint.
- IaC scanning: Checkov (Terraform), kube-linter or kube-score for K8s.
- Signature/provenance: Cosign (keyless OIDC) + SLSA provenance (optional).
- SARIF reporting to GitHub’s “Security > Code scanning alerts”.
