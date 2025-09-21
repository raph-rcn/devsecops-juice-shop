# DevSecOps Juice Shop
Wrapper repo to practice DevSecOps: CI scans (Gitleaks, Semgrep, Checkov, Hadolint),
SBOM (Syft), container scans (Trivy), DAST (ZAP), and image signing (Cosign).


## GitHub Actions

- Secrets scanning: Gitleaks (pre-commit + CI).
- SAST: Semgrep (JS/TS rules, OWASP Top 10).
- Dependency vulnerability: npm audit + Trivy (filesystem scan) or Snyk (optional).
- Container image scanning: Trivy/Grype.
- Dockerfile linting: Hadolint.
- IaC scanning: Checkov (Terraform), kube-linter or kube-score for K8s.
- DAST: OWASP ZAP baseline scan against ephemeral app.
- SBOM: Syft (CycloneDX/SPDX) + attach as artifact.
- Signature/provenance: Cosign (keyless OIDC) + SLSA provenance (optional).
- SARIF reporting to GitHub’s “Security > Code scanning alerts”.
