# devsecops-juice-shop
This is an attempt to create an end-to-end DevSecOps lab for the vulnerable OWASP Juice Shop, embedding security controls into the software development lifecycle with hands-on tooling.

This repo wraps OWASP Juice Shop to practice end-to-end DevSecOps:

- CI: SAST (Semgrep), secrets scan (Gitleaks), IaC scan (Checkov), Dockerfile lint (Hadolint)
- Build: container build, SBOM (Syft), image scan (Trivy), image signing (Cosign)
- DAST: OWASP ZAP against ephemeral service
