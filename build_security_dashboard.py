#!/usr/bin/env python3
from pathlib import Path
import json, re, pathlib, sys, os

ROOT = Path(os.environ.get("GITHUB_WORKSPACE", Path.cwd())).resolve()
README = ROOT / "README.md"

TRIVY_SARIF = ROOT / "trivy-image.sarif"
ZAP_JSON    = ROOT / "report_json.json"
SBOM_JSON   = ROOT / "sbom.cdx.json"

OUT_SVG     = ROOT / "security-dashboard.svg"        # optional (kept for future)
OUT_MD_FULL = ROOT / "SECURITY_FINDINGS.md"          # long form (also in README)

def load_json(p: pathlib.Path):
    if not p.exists():
        return None
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)

def trivy_counts(sarif):
    if not sarif:
        return {"total": 0, "by_sev": {}}
    runs = sarif.get("runs", [])
    total = 0
    by = {}
    # Map ruleId -> severity if available
    rule_sev = {}
    for r in runs:
        drv = r.get("tool", {}).get("driver", {})
        for rule in drv.get("rules", []) or []:
            rule_id = rule.get("id")
            sev = (rule.get("properties", {}) or {}).get("security-severity") \
                  or (rule.get("properties", {}) or {}).get("problem.severity") \
                  or (rule.get("properties", {}) or {}).get("severity")
            if rule_id and sev:
                rule_sev[rule_id] = str(sev).upper()
    for r in runs:
        for res in r.get("results", []) or []:
            total += 1
            sev = rule_sev.get(res.get("ruleId") or "", None)
            if not sev:
                # fallbacks: SARIF level or default
                sev = (res.get("level") or "warning").upper()
            sev = {"ERROR":"CRITICAL","WARNING":"HIGH","NOTE":"MEDIUM","INFO":"LOW"}.get(sev, sev)
            by[sev] = by.get(sev, 0) + 1
    return {"total": total, "by_sev": by}

def zap_counts(zap):
    if not zap:
        return {"total": 0, "by_risk": {},"alerts":[]}
    alerts = []
    total = 0
    by = {}
    # Baseline JSON typically: { "site": [{ "alerts": [ { "alert": "...", "risk": "Low|Medium|High", "instances":[...], ... } ]}]}
    sites = zap.get("site") or zap.get("sites") or []
    for s in sites:
        for a in s.get("alerts", []) or []:
            risk = (a.get("risk") or a.get("riskdesc") or "Info").split(" ")[0]
            risk = risk.capitalize()
            by[risk] = by.get(risk, 0) + 1
            total += 1
            # compact alert entry
            alerts.append({
                "name": a.get("alert") or a.get("name") or "Alert",
                "risk": risk,
                "count": len(a.get("instances", []) or []),
                "url": (a.get("instances",[{}])[0] or {}).get("uri") if a.get("instances") else None,
                "pluginId": a.get("pluginId"),
            })
    return {"total": total, "by_risk": by, "alerts": alerts}

def sbom_counts(sbom):
    # Syft CycloneDX: components array
    if not sbom:
        return {"components": 0}
    comps = sbom.get("components") or []
    return {"components": len(comps)}

def mermaid_pie(zap_total, trivy_total, sbom_components):
    # GitHub renders Mermaid in README – simplest circular chart.
    # We only include counts that exist (>0) so the chart looks clean.
    lines = ['```mermaid', 'pie title Security findings (Juice Shop)']
    if trivy_total > 0:
        lines.append(f'  "Image vulns (Trivy)" : {trivy_total}')
    if zap_total > 0:
        lines.append(f'  "DAST alerts (ZAP)" : {zap_total}')
    # SBOM isn’t vulns, but useful context:
    if sbom_components > 0:
        lines.append(f'  "SBOM components (Syft)" : {sbom_components}')
    lines.append('```')
    return "\n".join(lines)

def table_from_dict(d, left, right):
    if not d:
        return f"| {left} | {right} |\n|---|---|\n| (none) | 0 |\n"
    out = [f"| {left} | {right} |", "|---|---|"]
    for k,v in sorted(d.items(), key=lambda x: (-x[1], x[0])):
        out.append(f"| {k} | {v} |")
    return "\n".join(out) + "\n"

def zap_alerts_list(alerts):
    if not alerts:
        return "_No ZAP alerts found._\n"
    lines = []
    for a in alerts:
        head = f"- **{a['name']}** — _{a['risk']}_"
        if a.get("count"):
            head += f" (examples: {a['count']})"
        if a.get("pluginId"):
            head += f" [id:{a['pluginId']}]"
        if a.get("url"):
            head += f" — e.g. `{a['url']}`"
        lines.append(head)
    return "\n".join(lines) + "\n"

def build_md(zap, trivy, sbom):
    # Summary
    pie = mermaid_pie(zap["total"], trivy["total"], sbom["components"])
    parts = [ "## 🔒 Security dashboard (Juice Shop)\n", pie, "" ]

    # Trivy
    parts += [
        "### 🐳 Container image vulnerabilities (Trivy)",
        f"**Total:** {trivy['total']}\n",
        table_from_dict(trivy["by_sev"], "Severity", "Count"),
    ]

    # ZAP
    parts += [
        "### 🌐 DAST alerts (OWASP ZAP Baseline)",
        f"**Total:** {zap['total']}\n",
        table_from_dict(zap["by_risk"], "Risk", "Count"),
        "<details><summary>All ZAP alerts</summary>\n\n",
        zap_alerts_list(zap["alerts"]),
        "\n</details>\n",
    ]

    # SBOM
    parts += [
        "### 📦 SBOM (Syft)",
        f"**Components indexed:** {sbom['components']}\n",
        "_Note: SBOM components are not vulnerabilities, but help quantify the attack surface._\n",
    ]

    # Links to raw artifacts if present
    links = []
    if TRIVY_SARIF.exists():
        links.append("- Trivy SARIF: `trivy-image.sarif`")
    if ZAP_JSON.exists():
        links.append("- ZAP JSON: `report_json.json`")
    if SBOM_JSON.exists():
        links.append("- SBOM (CycloneDX): `sbom.cdx.json`")
    if links:
        parts += ["### 📎 Artifacts", *links, ""]

    return "\n".join(parts).strip() + "\n"

def replace_in_readme(new_block: str):
    if not README.exists():
        print(f"README.md not found at {README}", file=sys.stderr)
        sys.exit(1)
    text = README.read_text(encoding="utf-8")
    start = "<!-- security-dashboard:start -->"
    end   = "<!-- security-dashboard:end -->"
    pattern = re.compile(
        r"<!-- security-dashboard:start -->.*?<!-- security-dashboard:end -->",
        re.DOTALL
    )
    replacement = f"{start}\n\n{new_block}\n{end}"
    if pattern.search(text):
        text = pattern.sub(replacement, text)
    else:
        # append if markers missing
        text = text.rstrip() + "\n\n" + replacement + "\n"
    README.write_text(text, encoding="utf-8")

def main():
    trivy = trivy_counts(load_json(TRIVY_SARIF))
    zap   = zap_counts(load_json(ZAP_JSON))
    sbom  = sbom_counts(load_json(SBOM_JSON))
    md = build_md(zap, trivy, sbom)

    # write long form for reference as well
    OUT_MD_FULL.write_text(md, encoding="utf-8")

    # optional: leave a tiny SVG placeholder (Mermaid is the primary)
    OUT_SVG.write_text(
        "<svg xmlns='http://www.w3.org/2000/svg' width='10' height='10'></svg>",
        encoding="utf-8"
    )

    replace_in_readme(md)
    print("Security dashboard updated in README and SECURITY_FINDINGS.md")

if __name__ == "__main__":
    main()
