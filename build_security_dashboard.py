from pathlib import Path
import json, re, pathlib, sys, os
from collections import defaultdict, Counter

ROOT = Path(os.environ.get("GITHUB_WORKSPACE", Path.cwd())).resolve()
README = ROOT / "README.md"

TRIVY_SARIF = ROOT / "trivy-image.sarif"
ZAP_JSON    = ROOT / "report_json.json"
SBOM_JSON   = ROOT / "sbom.cdx.json"
GRYPE_SARIF = ROOT / "grype.sarif"

OUT_SVG     = ROOT / "security-dashboard.svg"
OUT_MD_FULL = ROOT / "SECURITY_FINDINGS.md"

def load_json(p: pathlib.Path):
    if not p.exists():
        return None
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)

# ---------- TRIVY ----------
def trivy_counts(sarif):
    if not sarif:
        return {"total": 0, "by_sev": {}}
    runs = sarif.get("runs", [])
    total = 0
    by = Counter()
    rule_sev = {}

    def norm_rule_sev(val):
        # try numeric first
        try:
            return float(val)
        except Exception:
            pass
        # map SARIF levels to buckets later
        s = str(val).strip()
        return s

    for r in runs:
        drv = r.get("tool", {}).get("driver", {})
        for rule in drv.get("rules", []) or []:
            rule_id = rule.get("id")
            props = (rule.get("properties", {}) or {})
            sev = (
                props.get("security-severity")
                or props.get("problem.severity")
                or props.get("severity")
            )
            if rule_id and sev is not None:
                rule_sev[rule_id] = norm_rule_sev(sev)

    for r in runs:
        for res in r.get("results", []) or []:
            total += 1
            sev = rule_sev.get(res.get("ruleId") or "")
            if sev is None:
                sev = res.get("level") or "warning"

            # normalize result-level severity:
            # - if numeric (CVSS-ish): keep number
            # - if text: map SARIF level -> bucket later
            if isinstance(sev, str):
                try:
                    sev = float(sev)
                except Exception:
                    sev = sev.strip().lower()

            by[str(sev)] += 1  # keep raw “label” for the raw table
    return {"total": total, "by_sev": dict(by)}

def trivy_bucket(label_or_number):
    """
    Map raw Trivy severities (numbers like 5.5, 7.8, etc. or text) into 4 buckets:
    Critical (≥9.0), High (≥7.0), Medium (≥4.0), Low (<4.0).
    """
    # numeric?
    try:
        x = float(label_or_number)
        if x >= 9.0: return "Critical"
        if x >= 7.0: return "High"
        if x >= 4.0: return "Medium"
        return "Low"
    except Exception:
        pass

    s = str(label_or_number).strip().lower()
    if s.startswith("crit"):   return "Critical"
    if s.startswith("high"):   return "High"
    if s.startswith("med"):    return "Medium"
    if s in {"moderate"}:      return "Medium"
    if s in {"error"}:         return "Critical"   # SARIF level
    if s in {"warning"}:       return "High"       # SARIF level
    if s in {"note"}:          return "Medium"     # SARIF level
    if s in {"info","information","informational"}: return "Low"
    return "Low"

def trivy_buckets_4(trivy):
    buckets = Counter()
    for raw_label, n in (trivy.get("by_sev") or {}).items():
        buckets[trivy_bucket(raw_label)] += n
    return dict(buckets)

def mermaid_pie_from_counts(title:str, counts:dict):
    lines = ['```mermaid', f'pie title {title}']
    # stable order for readability
    order = ["Critical","High","Medium","Low","Negligible","Unknown","Info","Informational"]
    for k in order:
        if counts.get(k, 0):
            lines.append(f'  "{k}" : {counts[k]}')
    # any other keys
    for k, v in counts.items():
        if k not in order and v:
            lines.append(f'  "{k}" : {v}')
    lines.append('```')
    return "\n".join(lines)

# ---------- ZAP ----------
def zap_counts(zap):
    if not zap:
        return {"total": 0, "by_risk": {},"alerts":[]}
    alerts = []
    total = 0
    by = Counter()
    sites = zap.get("site") or zap.get("sites") or []
    for s in sites:
        for a in s.get("alerts", []) or []:
            risk = (a.get("risk") or a.get("riskdesc") or "Info").split(" ")[0]
            risk = risk.capitalize()
            by[risk] += 1
            total += 1
            alerts.append({
                "name": a.get("alert") or a.get("name") or "Alert",
                "risk": risk,
                "count": len(a.get("instances", []) or []),
                "url": (a.get("instances",[{}])[0] or {}).get("uri") if a.get("instances") else None,
                "pluginId": a.get("pluginId"),
            })
    return {"total": total, "by_risk": dict(by), "alerts": alerts}

# ---------- SBOM ----------
def sbom_counts(sbom):
    if not sbom:
        return {"components": 0}
    comps = sbom.get("components") or []
    return {"components": len(comps)}

# ---------- GRYPE ----------
def grype_counts_and_rows(sarif):
    """
    Return:
      counts: dict(severity -> n) where severity in {Critical,High,Medium,Low,Negligible,Unknown}
      rows: list of dicts (non-negligible only): {id, pkg, version, severity, fix, location}
      negligible_count: int
    """
    counts = Counter()
    rows = []
    negligible_count = 0
    if not sarif:
        return dict(counts), rows, negligible_count

    # Build ruleId -> (severity, shortTitle) map as a fallback
    rules = {}
    for run in sarif.get("runs", []):
        drv = run.get("tool", {}).get("driver", {})
        for rule in drv.get("rules", []) or []:
            rid = rule.get("id")
            props = rule.get("properties", {}) or {}
            sev = (props.get("severity") or props.get("problem.severity") or
                   props.get("security-severity") or rule.get("defaultConfiguration", {}).get("level"))
            if isinstance(sev, (int, float)):
                sev = float(sev)
            rules[rid] = {
                "severity": str(sev).lower() if isinstance(sev, str) else sev,
                "title": rule.get("shortDescription", {}).get("text") or rule.get("name") or "",
            }

    def norm_sev(val):
        if val is None:
            return "Unknown"
        if isinstance(val, (int, float)):
            # if numeric (rare), map CVSS-ish into bands
            x = float(val)
            if x >= 9.0: return "Critical"
            if x >= 7.0: return "High"
            if x >= 4.0: return "Medium"
            if x > 0.0:  return "Low"
            return "Unknown"
        s = str(val).strip().lower()
        if s.startswith("crit"): return "Critical"
        if s.startswith("high"): return "High"
        if s.startswith("med"):  return "Medium"
        if s.startswith("low"):  return "Low"
        if s.startswith("negl"): return "Negligible"
        if s in {"unknown", "none"}: return "Unknown"
        # map SARIF levels if present
        if s in {"error"}:   return "Critical"
        if s in {"warning"}: return "High"
        if s in {"note"}:    return "Medium"
        if s in {"info"}:    return "Low"
        return s.capitalize()

    def first(xs, key):
        for x in xs or []:
            v = x.get(key)
            if v:
                return v
        return None

    for run in sarif.get("runs", []):
        res_list = run.get("results", []) or []
        artifacts = run.get("artifacts", []) or []
        for res in res_list:
            rid = res.get("ruleId")
            res_props = res.get("properties", {}) or {}
            sev = res_props.get("severity") or res.get("level") or (rules.get(rid, {}).get("severity"))
            sev = norm_sev(sev)
            counts[sev] += 1

            # Build a row (skip negligible for the main table)
            if sev == "Negligible":
                negligible_count += 1
                continue

            # Try to extract vuln id, package, version, fix, location
            vuln_id = rid or res_props.get("vulnerability.id") or res.get("rule", {}).get("id") or "N/A"

            # package/version: Grype usually formats in message text; try to parse
            msg = (res.get("message", {}) or {}).get("text") or ""
            pkg = ""
            version = ""
            # Heuristics: look for "package@version" or "pkg=..., version=..."
            m = re.search(r'([A-Za-z0-9_.+\-:/]+)@([0-9][A-Za-z0-9+._\-:]*)', msg)
            if m:
                pkg, version = m.group(1), m.group(2)
            else:
                # fallbacks via properties
                pkg = res_props.get("package.name") or res_props.get("pkg.name") or ""
                version = res_props.get("package.version") or res_props.get("pkg.version") or ""

            fix = res_props.get("fix.state") or res_props.get("fix") or ""
            # location: from locations -> physicalLocation -> artifactLocation -> uri
            loc_uri = ""
            locs = res.get("locations", []) or []
            if locs:
                auri = (locs[0].get("physicalLocation", {}) or {}).get("artifactLocation", {}) or {}
                loc_uri = auri.get("uri") or ""

            rows.append({
                "id": vuln_id,
                "pkg": pkg,
                "version": version,
                "severity": sev,
                "fix": fix,
                "location": loc_uri,
            })

    return dict(counts), rows, negligible_count

# ---------- RENDER HELPERS ----------
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

def grype_rows_table(rows, negligible_count):
    if not rows and negligible_count == 0:
        return "_No vulnerabilities reported by Grype._\n"
    # Build markdown table (non-negligible only)
    lines = [
        "| Vulnerability | Package | Version | Severity | Fix | Location |",
        "|---|---|---|---|---|---|",
    ]
    # sort by severity weight then id
    sev_weight = {"Critical":4,"High":3,"Medium":2,"Low":1,"Unknown":0}
    for r in sorted(rows, key=lambda x: (-sev_weight.get(x["severity"], 0), x["id"], x["pkg"])):
        lines.append(f"| `{r['id']}` | `{r['pkg'] or '-'}` | `{r['version'] or '-'}` | {r['severity']} | `{r['fix'] or '-'}` | `{r['location'] or '-'}` |")
    if negligible_count:
        lines.append(f"| _Negligible_ | _omitted_ |  | _Negligible_ |  |  |")
        lines.append(f"\n> **Note:** {negligible_count} negligible finding(s) omitted from the table.\n")
    return "\n".join(lines) + "\n"

# ---------- PAGE BUILD ----------
def build_md(zap, trivy, sbom, grype_counts, grype_rows, grype_negl):
    parts = [ "## 🔒 Security dashboard (Juice Shop)\n" ]

    # Trivy severity pie (Critical/High/Medium/Low)
    t4 = trivy_buckets_4(trivy)
    if sum(t4.values()):
        parts += [ # expand to show the raw numeric severities
            "<details><summary>Raw severity values (from SARIF)</summary>\n\n",
            table_from_dict(trivy["by_sev"], "Severity (raw)", "Count"),
            "\n</details>\n",
        ]

    # ZAP alerts pie
    if sum((zap.get("by_risk") or {}).values()):
        parts += [
            mermaid_pie_from_counts("DAST alerts (ZAP)", zap["by_risk"]),
            ""
        ]

    # Grype CVE pie (Critical/High/Medium/Low/Negligible/Unknown)
    if sum(grype_counts.values()):
        parts += [ # Render even if counts are zero to keep the section visible.
            mermaid_pie_from_counts("Container CVEs (Grype)", {
                "Critical": grype_counts.get("Critical", 0),
                "High": grype_counts.get("High", 0),
                "Medium": grype_counts.get("Medium", 0),
                "Low": grype_counts.get("Low", 0),
                "Negligible": grype_counts.get("Negligible", 0),
                "Unknown": grype_counts.get("Unknown", 0),
            }),
            ""
        ]

    # --- Sections ---

    # Trivy (keep the detailed table you had)
    parts += [
        "### 🐳 Container image vulnerabilities (Trivy)",
        f"**Total:** {trivy['total']}\n",
        table_from_dict(trivy["by_sev"], "Severity", "Count"),
    ]

    # ZAP section (unchanged)
    parts += [
        "### 🌐 DAST alerts (OWASP ZAP Baseline)",
        f"**Total:** {zap['total']}\n",
        table_from_dict(zap["by_risk"], "Risk", "Count"),
        "<details><summary>All ZAP alerts</summary>\n\n",
        zap_alerts_list(zap["alerts"]),
        "\n</details>\n",
    ]

    # Grype details (collapsible, with negligible summarized only)
    parts += [
        "### 🧰 Container CVEs (Grype from SBOM)",
        f"**Total (all severities):** {sum(grype_counts.values())}\n",
        "<details><summary>Show CVE table (Negligible omitted)</summary>\n\n",
        grype_rows_table(grype_rows, grype_negl),
        "\n</details>\n",
    ]

    # SBOM
    parts += [
        "### 📦 SBOM (Syft)",
        f"**Components indexed:** {sbom['components']}\n",
        "_Note: SBOM components are not vulnerabilities, but help quantify the attack surface._\n",
    ]

    # Artifacts
    links = []
    if TRIVY_SARIF.exists():
        links.append("- Trivy SARIF: `trivy-image.sarif`")
    if ZAP_JSON.exists():
        links.append("- ZAP JSON: `report_json.json`")
    if SBOM_JSON.exists():
        links.append("- SBOM (CycloneDX): `sbom.cdx.json`")
    if GRYPE_SARIF.exists():
        links.append("- Grype SARIF: `grype.sarif`")
        if (ROOT / "grype.txt").exists():
            links.append("- Grype Table: `grype.txt`")
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
        text = text.rstrip() + "\n\n" + replacement + "\n"
    README.write_text(text, encoding="utf-8")

def main():
    trivy = trivy_counts(load_json(TRIVY_SARIF))
    zap   = zap_counts(load_json(ZAP_JSON))
    sbom  = sbom_counts(load_json(SBOM_JSON))
    grc, gr_rows, gr_negl = grype_counts_and_rows(load_json(GRYPE_SARIF))

    md = build_md(zap, trivy, sbom, grc, gr_rows, gr_negl)

    OUT_MD_FULL.write_text(md, encoding="utf-8")
    OUT_SVG.write_text("<svg xmlns='http://www.w3.org/2000/svg' width='10' height='10'></svg>", encoding="utf-8")

    replace_in_readme(md)
    print("Security dashboard updated in README and SECURITY_FINDINGS.md")

if __name__ == "__main__":
    main()
