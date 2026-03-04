from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import math
import re
import csv
import urllib.request
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Iterable
from collections import defaultdict, Counter
from markupsafe import Markup

try:
    from jinja2 import Environment, select_autoescape
except ImportError as e:  
    raise RuntimeError(
        "Module 5 requires Jinja2. Install with: pip install jinja2"
    ) from e

# ---------------------------------------------------------------------------
# External Database Management (Auto-Update with Resilience)
# ---------------------------------------------------------------------------

def should_update_file(file_path: Path, max_age_hours: int = 24) -> bool:
    """
    Returns True if the file does not exist or is older than max_age_hours..
    """
    if not file_path.exists():
        return True

    try:
        mtime = file_path.stat().st_mtime
        age_seconds = time.time() - mtime
        age_hours = age_seconds / 3600
        if age_hours > max_age_hours:
            print(f"[Module5] '{file_path.name}' is {age_hours:.1f} hours old. Attempting to update...")
            return True
        return False
    except Exception:
        return True


def ensure_edb_database(csv_path: Path) -> None:
    EDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

    if not should_update_file(csv_path):
        return

    print(f"[Module5] Downloading Exploit-DB (files_exploits.csv)...")
    try:
        req = urllib.request.Request(
            EDB_CSV_URL,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as response, csv_path.open("wb") as out_file:
            shutil.copyfileobj(response, out_file)
        print(f"[Modulo5] Exploit-DB download complete.")
    except Exception as e:
        print(f"[Modulo5] WARNING: Unable to update Exploit-DB: {e}")
        if csv_path.exists():
            print("[Module5] Using existing local version (even if outdated).")
        else:
            print("[Module5] The report will be generated without the extra Exploit-DB check (file not present).")


def ensure_cisa_database(json_path: Path) -> None:
    CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    if not should_update_file(json_path):
        return

    print(f"[Module5] Downloading CISA KEV Catalog...")
    try:
        req = urllib.request.Request(
            CISA_URL,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as response, json_path.open("wb") as out_file:
            shutil.copyfileobj(response, out_file)
        print(f"[Module5] CISA download complete.")
    except Exception as e:
        print(f"[Module5] WARNING: Unable to update CISA KEV: {e}")
        if json_path.exists():
            print("[Module5] Using existing local version (even if outdated).")
        else:
            print("[Module5] The report will be generated without CISA highlights (file not present).")


def load_edb_cve_map(csv_path: Path) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    if not csv_path.exists():
        return mapping

    print(f"[Module5] Loading CVE -> Exploit-DB map...")
    try:
        with csv_path.open("r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                edb_id = row.get("id")
                codes = row.get("codes")

                if not edb_id or not codes:
                    continue

                for code in codes.split(";"):
                    code = code.strip().upper()
                    if code.startswith("CVE-"):
                        mapping[code] = edb_id
    except Exception as e:
        print(f"[Module5] ERROR reading EDB CSV: {e}")

    print(f"[Module5] Mapped {len(mapping)} CVEs connected to public exploits (EDB).")
    return mapping


def load_cisa_cve_map(json_path: Path) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    if not json_path.exists():
        return mapping

    print(f"[Module5] Loading CISA KEV map...")
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        vulns = data.get("vulnerabilities", [])
        for item in vulns:
            cve_id = item.get("cveID")
            if cve_id:
                mapping[cve_id] = "CISA KEV"
    except Exception as e:
        print(f"[Module5] ERROR reading CISA JSON {e}")

    print(f"[Module5] Mapped {len(mapping)} CVEs confirmed as exploited (CISA).")
    return mapping


# ---------------------------------------------------------------------------
# Utility Functions and Statistics Calculation
# ---------------------------------------------------------------------------

def get_all_critical_packages(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    critical_pkgs = [
        item["package"]
        for item in items
        if (item.get("severity") or "").upper() == "CRITICAL"
    ]

    if not critical_pkgs:
        return []

    counts = Counter(critical_pkgs)
    result = [
        {"name": pkg, "count": count}
        for pkg, count in counts.items()
    ]
    result.sort(key=lambda x: (-x["count"], x["name"]))
    return result


def group_similar_packages(data):
    grouped_data = {}
    details = {}

    for package, count in data:
        pkg_lower = package.lower()
        if "mariadb" in pkg_lower:
            group_name = "mariadb"
        elif "php" in pkg_lower:
            group_name = "php"
        elif "apache" in pkg_lower:
            group_name = "apache"
        elif "libc" in pkg_lower or "openssl" in pkg_lower or "libssl" in pkg_lower:
            group_name = "system-libs"
        elif "perl" in pkg_lower:
            group_name = "perl"
        elif "postgresql" in pkg_lower or "sqlite" in pkg_lower:
            group_name = "databases"
        elif "rsync" in pkg_lower or "tar" in pkg_lower or "gzip" in pkg_lower:
            group_name = "utilities"
        elif "security" in pkg_lower:
            group_name = "security"
        else:
            group_name = "others"

        if group_name in grouped_data:
            grouped_data[group_name] += count
            details[group_name].append((package, count))
        else:
            grouped_data[group_name] = count
            details[group_name] = [(package, count)]

    sorted_groups = sorted(
        [(label, grouped_data[label], details[label]) for label in grouped_data],
        key=lambda x: x[1],
        reverse=True
    )
    return sorted_groups


def svg_package_pie(data: List[Tuple[str, int]], size: int = 140) -> Dict[str, str]:
    if not data:
        return {"svg": "", "legend": "<p class='muted'>Nessun dato disponibile.</p>"}

    total = sum(count for _, count in data)
    if total == 0:
        return {"svg": "", "legend": "<p class='muted'>Nessun dato disponibile.</p>"}

    grouped_data = group_similar_packages(data)

    raw_percentages = [(count / total) * 100 for _, count, _ in grouped_data]
    int_percentages = [math.floor(p) for p in raw_percentages]

    diff = 100 - sum(int_percentages)

    decimal_parts = [((p - math.floor(p)), i) for i, p in enumerate(raw_percentages)]
    decimal_parts.sort(key=lambda x: x[0], reverse=True)

    for i in range(int(diff)):
        index_to_bump = decimal_parts[i][1]
        int_percentages[index_to_bump] += 1

    r = size / 2
    cx = cy = r

    svg_parts = [
        f'<svg class="pie-svg" width="{size}" height="{size}" '
        f'viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">'
    ]

    colors = ["#b71c1c", "#e53935", "#fb8c00", "#43a047", "#90a4ae", "#1e88e5", "#8e24aa"]
    cumulative = 0.0
    text_labels = []

    for i, (label, count, _) in enumerate(grouped_data):
        value = count / total
        start = cumulative * 2 * math.pi
        end = (cumulative + value) * 2 * math.pi

        x1 = cx + r * math.cos(start)
        y1 = cy + r * math.sin(start)
        x2 = cx + r * math.cos(end)
        y2 = cy + r * math.sin(end)
        large_arc = 1 if (end - start) > math.pi else 0

        d = f"M {cx} {cy} L {x1} {y1} A {r} {r} 0 {large_arc} 1 {x2} {y2} Z"
        color = colors[i % len(colors)]
        svg_parts.append(f'<path d="{d}" fill="{color}" stroke="white" stroke-width="1" />')

        if value > 0.05:
            mid_angle = (start + end) / 2.0
            label_r = r * 0.65
            lx = cx + label_r * math.cos(mid_angle)
            ly = cy + label_r * math.sin(mid_angle)
            short_label = label[:9] + "." if len(label) > 10 else label

            text_labels.append(
                f'<text x="{lx}" y="{ly}" text-anchor="middle" dominant-baseline="middle" '
                f'font-size="10" font-family="sans-serif" fill="white" font-weight="bold" '
                f'style="text-shadow: 1px 1px 2px black;">{short_label}</text>'
            )
        cumulative += value

    svg_parts.extend(text_labels)
    svg_parts.append("</svg>")
    svg_str = "".join(svg_parts)

    legend_parts = ['<ul class="pie-legend">']
    for i, (label, count, details) in enumerate(grouped_data):
        pct = int_percentages[i]
        color = colors[i % len(colors)]
        legend_parts.append(
            f'<li><span class="pie-swatch" style="background:{color}"></span>'
            f"<strong>{label}</strong> ({count}, {pct}%)"
        )
        if details:
            legend_parts.append('<ul class="pie-sublegend">')
            sorted_details = sorted(details, key=lambda x: x[1], reverse=True)
            for sub_package, sub_count in sorted_details:
                sub_pct = int(round((sub_count / total) * 100))
                pct_str = f"{sub_pct}%" if sub_pct > 0 else "<1%"
                legend_parts.append(f"<li>{sub_package} ({sub_count}, {pct_str})</li>")

            legend_parts.append('<li style="clear:both; float:none; width:100%; height:0; margin:0; padding:0; border:none;"></li>')
            legend_parts.append("</ul>")
        legend_parts.append("</li>")
    legend_parts.append("</ul>")

    legend_str = "".join(legend_parts)

    return {"svg": svg_str, "legend": legend_str}


def svg_pie_chart(data: dict, size: int = 140) -> Dict[str, str]:
    if not data:
        return {"svg": "", "legend": "<p class='muted'>Nessun dato disponibile.</p>"}

    items = sorted(data.items(), key=lambda kv: kv[1], reverse=True)
    total = sum(count for _label, count in items)
    if total == 0:
        return {"svg": "", "legend": "<p class='muted'>Nessun dato disponibile.</p>"}

    r = size / 2.0
    cx = cy = r

    svg_parts = [f'<svg class="pie-svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">']
    sev_colors = {
        "CRITICAL": "#b71c1c",
        "HIGH": "#e53935",
        "MEDIUM": "#fb8c00",
        "LOW": "#43a047",
        "NEGLIGIBLE": "#c5e1a5",
        "UNKNOWN": "#90a4ae",
        "INFO": "#0288d1"
    }
    fallback_colors = ["#b71c1c", "#e53935", "#fb8c00", "#43a047", "#90a4ae"]

    cumulative = 0.0
    for i, (label, count) in enumerate(items):
        value = count / total
        start = cumulative * 2 * math.pi
        end = (cumulative + value) * 2 * math.pi
        cumulative += value

        x1 = cx + r * math.cos(start)
        y1 = cy + r * math.sin(start)
        x2 = cx + r * math.cos(end)
        y2 = cy + r * math.sin(end)
        large_arc = 1 if (end - start) > math.pi else 0
        d = f"M {cx} {cy} L {x1} {y1} A {r} {r} 0 {large_arc} 1 {x2} {y2} Z"

        label_upper = label.upper()
        if label_upper in sev_colors:
            color = sev_colors[label_upper]
        else:
            color = fallback_colors[i % len(fallback_colors)]
        svg_parts.append(f'<path d="{d}" fill="{color}" />')
    svg_parts.append("</svg>")
    svg_str = "".join(svg_parts)

    legend_parts = ['<ul class="pie-legend">']
    for i, (label, count) in enumerate(items):
        pct = int(round((count / total) * 100))
        label_upper = label.upper()
        if label_upper in sev_colors:
            color = sev_colors[label_upper]
        else:
            color = fallback_colors[i % len(fallback_colors)]
        legend_parts.append(f'<li><span class="pie-swatch" style="background:{color}"></span>{label} ({count}, {pct}%)</li>')
    legend_parts.append("</ul>")
    legend_str = "".join(legend_parts)

    return {"svg": svg_str, "legend": legend_str}


def svg_histogram(data: Iterable[Tuple[str, int]], max_bars: int = 10, total_width: int = 520, label_width: int = 160, bar_height: int = 20) -> str:
    grouped_data = group_similar_packages(data)
    items = grouped_data[:max_bars]

    if not items:
        return "<p class='muted'>Nessun dato disponibile.</p>"

    max_val = max(count for _, count, _ in items) or 1
    chart_width = total_width - label_width - 50
    height = (len(items) * (bar_height + 8)) + 10

    svg = [f'<svg width="{total_width}" height="{height}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Histogram">']
    colors = ["#b71c1c", "#e53935", "#fb8c00", "#43a047", "#90a4ae", "#1e88e5", "#8e24aa"]

    y = 10
    for i, (label, count, details) in enumerate(items):
        color = colors[i % len(colors)]
        bar_w = int((count / max_val) * chart_width)

        safe_label = (label[:20] + "...") if len(label) > 23 else label
        svg.append(f'<text x="4" y="{y + 15}" font-size="12" font-weight="bold" font-family="sans-serif" fill="#333">{safe_label}</text>')
        svg.append(f'<rect x="{label_width}" y="{y}" width="{bar_w}" height="{bar_height}" rx="4" fill="{color}" />')
        svg.append(f'<text x="{label_width + bar_w + 8}" y="{y + 15}" font-size="12" font-family="sans-serif" fill="#444" font-weight="bold">{count}</text>')
        y += bar_height + 8

    svg.append("</svg>")
    return "".join(svg)


# ---------------------------------------------------------------------------
# Normalizations (Modules 2, 3, 4)
# ---------------------------------------------------------------------------

def _normalize_vulns(data: Optional[Dict[str, Any]], edb_map: Dict[str, str], cisa_map: Dict[str, str]) -> Dict[str, Any]:
    if not data:
        return {
            "items": [],
            "stats": {"total": 0, "by_severity": {}},
            "coverage": {"trivy_only": 0, "grype_only": 0, "both": 0},
            "top5_critical": [],
        }

    stats_raw = data.get("stats") or {}
    by_severity = stats_raw.get("by_severity") or {}

    total = stats_raw.get("total_vulnerabilities")
    if total is None:
        total = sum(int(v) for v in by_severity.values()) if by_severity else 0

    items: List[Dict[str, Any]] = []
    primary_source = str(data.get("primary_source") or "merged")
    raw_list = data.get("vulnerabilities")
    if raw_list is None:
        raw_list = data.get("top_vulnerabilities", []) or []

    # --- MAP OF CERTAIN SOURCES AND RELATED LABELS ---
    EXPLOIT_SOURCE_MAP = {
        "exploit-db.com": "EDB",
        "packetstormsecurity.com": "Packet",
    }

    for v in raw_list:
        vuln_id = str(v.get("vuln_id") or "")
        sources = v.get("sources") or []
        if isinstance(sources, list):
            source_str = ", ".join(str(s) for s in sources)
        else:
            source_str = str(sources)

        refs = v.get("references")
        if not isinstance(refs, list):
            refs = []

         # --- COLLECT ALL LOGIC + CSV ENRICHMENT ---
        verified_links = []  # List of dictionaries: {"url": ..., "label": ..., "origin": ...}
        seen_urls = set()    # To avoid exact duplicates
        found_labels = set() # To know which types we have already found (e.g., EDB)

        # 1. Collect links found in the scanner report
        for ref in refs:
            ref_str = str(ref).lower()
            original_ref = str(ref)

            if original_ref in seen_urls:
                continue

            for domain, label in EXPLOIT_SOURCE_MAP.items():
                if domain in ref_str:
                    verified_links.append({
                        "label": label,
                        "url": original_ref,
                        "origin": "scanner"  # <--- Origine: SCANNER
                    })
                    seen_urls.add(original_ref)
                    found_labels.add(label)
                    break

        # 2. EXTRA CHECK: If we haven't found an EDB link, check the CSV file
        if "EDB" not in found_labels and vuln_id in edb_map:
            edb_id = edb_map[vuln_id]
            edb_url = f"https://www.exploit-db.com/exploits/{edb_id}"

            # Add the link generated from the CSV
            verified_links.insert(0, {  # Insert at the top
                "label": "EDB",
                "url": edb_url,
                "origin": "csv"  # <--- Origin: CSV (Local enrichment)
            })

        # 3. CISA KEV CHECK (New)
        # If the CVE is in the CISA catalog, we add it with the highest priority
        if vuln_id in cisa_map:
            verified_links.insert(0, {
                "label": "CISA KEV",
                "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={vuln_id}",
                "origin": "cisa"  # <--- Origin: CISA
            })

        items.append(
            {
                "id": vuln_id,
                "package": str(v.get("pkg") or ""),
                "installed": str(v.get("installed") or ""),
                "severity": str(v.get("severity") or ""),
                "fixed": str(v.get("fixed_version") or "-"),
                "cvss": v.get("cvss") if v.get("cvss") is not None else "",
                "source": source_str or primary_source,
                "references": refs,
                "verified_links": verified_links,
            }
        )

    coverage_raw = data.get("coverage") or {}
    coverage = {
        "trivy_only": int(coverage_raw.get("trivy_only", 0)),
        "grype_only": int(coverage_raw.get("grype_only", 0)),
        "both": int(coverage_raw.get("both", 0)),
    }

    return {
        "items": items,
        "stats": {"total": int(total), "by_severity": by_severity},
        "coverage": coverage,
    }


def _normalize_config(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not data:
        return {
            "findings": [],
            "stats": {"total": 0, "by_severity": {}},
            "dive": None,
        }

    counts = data.get("counts") or {}
    total = counts.get("total") or 0
    by_sev = counts.get("by_severity") or {}

    findings_raw = data.get("findings") or []
    findings = []
    for f in findings_raw:
        findings.append(
            {
                "id": str(f.get("id") or ""),
                "description": str(f.get("description") or ""),
                "severity": str(f.get("severity") or "Info"),
                "hint": str(f.get("hint") or ""),
            }
        )

    dive = None
    dive_raw = data.get("dive_summary")
    if dive_raw:
        wasted_bytes = dive_raw.get("wasted_bytes")
        if wasted_bytes is not None:
            try:
                wb = float(wasted_bytes)
                if wb >= 1024**3:
                    wasted_h = f"{wb/1024**3:.1f}GB"
                elif wb >= 1024**2:
                    wasted_h = f"{wb/1024**2:.1f}MB"
                elif wb >= 1024:
                    wasted_h = f"{wb/1024:.1f}KB"
                else:
                    wasted_h = f"{wb:.0f}B"
            except Exception:
                wasted_h = None
        else:
            wasted_h = None

        dive = {
            "efficiency_score": dive_raw.get("efficiency_score"),
            "wasted_bytes": wasted_bytes,
            "wasted_bytes_h": wasted_h,
        }

    return {
        "findings": findings,
        "stats": {"total": int(total), "by_severity": by_sev},
        "dive": dive,
    }


def _shorten_rootfs_path(path: str) -> str:
    import os
    if not path:
        return ""
    lower = path.lower()
    idx = lower.find("rootfs")
    if idx == -1:
        return os.path.basename(path)
    return path[idx:]


def _find_rootfs_prefix(paths: List[str]) -> str:
    if not paths:
        return ""
    norm_paths = [p.replace("/", "\\") for p in paths if p]
    if not norm_paths:
        return ""

    parts_list: List[List[str]] = [p.split("\\") for p in norm_paths]
    min_len = min(len(p) for p in parts_list)
    common: List[str] = []

    for i in range(min_len):
        segment = parts_list[0][i]
        if all(p[i].lower() == segment.lower() for p in parts_list[1:]):
            common.append(segment)
            if segment.lower() == "rootfs":
                break
        else:
            break

    if not common:
        return ""
    return "\\".join(common)


def _normalize_secrets(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not data:
        return {
            "findings": [],
            "stats": {"total": 0, "by_severity": {}, "by_type": {}},
            "common_prefix": "",
        }

    raw_findings = data.get("findings") or []
    all_paths: List[str] = [str(f.get("file_path") or "") for f in raw_findings]
    rootfs_prefix = _find_rootfs_prefix(all_paths)

    findings: List[Dict[str, Any]] = []
    by_sev: Dict[str, int] = {}
    by_type: Dict[str, int] = {}

    for f, full_path in zip(raw_findings, all_paths):
        rec = dict(f)
        rec["short_file_path"] = _shorten_rootfs_path(full_path)

        lower = full_path.lower()
        display = full_path
        if rootfs_prefix and lower.startswith(rootfs_prefix.lower()):
            display = full_path[len(rootfs_prefix):]
        else:
            idx = lower.find("rootfs")
            if idx != -1:
                display = full_path[idx + len("rootfs"):]

        display = display.lstrip("\\/")
        rec["display_file_path"] = display or full_path

        sev = (rec.get("severity") or "").capitalize() or "Unknown"
        t = str(rec.get("type") or "unknown")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_type[t] = by_type.get(t, 0) + 1

        findings.append(rec)

    stats = {
        "total": int(data.get("total_findings") or len(findings)),
        "by_severity": by_sev,
        "by_type": by_type,
        "by_rule": data.get("counts_by_rule", {}) or {},
    }
    return {
        "findings": findings,
        "stats": stats,
        "common_prefix": rootfs_prefix,
    }


# ---------------------------------------------------------------------------
# HTML Template
# ---------------------------------------------------------------------------

def _chunk_wrap(s: str, width: int = 60) -> Markup:
    if not s:
        return Markup("")
    s = str(s)
    chunks = [s[i: i + width] for i in range(0, len(s), width)]
    return Markup("<br>".join(chunks))


def _insert_wbr_breaks(s: str) -> str:
    if not s:
        return ""
    out = []
    for ch in str(s):
        out.append(ch)
        if ch in "_/.\\":  # keep same behavior
            out.append("<wbr>")
    return "".join(out)


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Container Security Report – {{ image_name }}</title>
  <style>
    body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 1.5rem; }
    h1, h2, h3 { color: #222; }

    table {
      border-collapse: collapse;
      width: 100%;
      margin-bottom: 1.5rem;
      font-size: 0.9rem;
      table-layout: fixed;
    }

    th, td {
      border: 1px solid #ccc;
      padding: 0.25rem 0.4rem;
      vertical-align: top;
      word-wrap: break-word;
      overflow-wrap: break-word;
    }

    th {
      background-color: #f5f5f5;
      text-align: left;
    }

    tr:nth-child(even) {
      background-color: #fafafa;
    }

    pre {
      white-space: pre-wrap;
      font-size: 0.8rem;
    }

    code {
      font-family: "Cascadia Code", "Fira Code", Consolas, monospace;
      font-size: 0.8rem;
    }

    code.prefix-path {
      word-break: normal;
    }

    .pill { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; }
    .sev-CRITICAL { background:#b71c1c; color:#fff; }
    .sev-HIGH { background:#e53935; color:#fff; }
    .sev-MEDIUM { background:#fb8c00; color:#000; }
    .sev-LOW { background:#43a047; color:#fff; }
    .sev-NEGLIGIBLE { background:#c5e1a5; color:#000; }
    .sev-INFO, .sev-UNDEFINED, .sev-UNKNOWN { background:#90a4ae; color:#000; }
    .section { margin-bottom: 2rem; }
    .muted { color:#666; font-size:0.85rem; }
    .counter { font-weight:bold; }
    .small { font-size:0.8rem; }
    .badge { padding:0.15rem 0.4rem; border-radius:999px; background:#e3f2fd;
             margin-right:0.3rem; font-size:0.75rem; }

    /* LAYOUT A GRIGLIA CON TABELLE PER WKHTMLTOPDF */
    .layout-grid {
        width: 100%;
        border: none;
        border-collapse: collapse;
        margin-bottom: 1rem;
        page-break-inside: avoid;
    }
    .layout-grid td {
        border: none;
        padding: 5px;
        vertical-align: top;
    }

    .col-narrow { width: 160px; }
    .col-chart-svg { width: 65%; }
    .col-chart-pie { width: 35%; }

    .pie-svg { width: 140px; height: 140px; }
    .pie-legend { list-style: none; padding: 0; margin: 0; font-size: 0.8rem; }
    .pie-legend > li { margin-bottom: 0.5rem; border-bottom: 1px solid #f0f0f0; padding-bottom: 0.3rem; }
    .pie-legend > li:last-child { border-bottom: none; }
    .pie-swatch { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 0.35rem; }

    .pie-sublegend { padding: 0; margin: 0.25rem 0 0 0; list-style: none; overflow: hidden; }
    .pie-sublegend li { display: inline-block; width: 32%; vertical-align: top; font-size: 0.75rem; color: #555; margin-bottom: 0.1rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; padding-right: 5px; box-sizing: border-box; page-break-inside: avoid; break-inside: avoid; }
    .pie-sublegend li::before { content: "• "; color: #ccc; }

    .top-packages-table {
        margin-top: 1rem;
        margin-bottom: 1.5rem;
        width: 100%;
        border: 1px solid #ddd;
    }
    .top-packages-table th { background-color: #ffcdd2; color: #b71c1c; }
    .top-packages-table td { font-weight: bold; }

    @media print {
        .pie-sublegend li { width: 32%; font-size: 0.7rem; }
    }
  </style>

  <script>
    function filterBySeverity(selectId, tableId) {
      const sel = document.getElementById(selectId);
      const value = sel ? sel.value : 'ALL';
      const rows = document.querySelectorAll('#' + tableId + ' tbody tr');
      rows.forEach(row => {
        const sevCell = row.getAttribute('data-severity') || '';
        if (!value || value === 'ALL' || sevCell === value) {
          row.style.display = '';
        } else {
          row.style.display = 'none';
        }
      });
    }

    function filterVulns() {
      const sevSelect = document.getElementById('vulnFilter');
      const srcSelect = document.getElementById('vulnSourceFilter');
      const searchInput = document.getElementById('vulnSearch');

      const sevValue = sevSelect ? sevSelect.value : 'ALL';
      const srcValue = srcSelect ? srcSelect.value : 'ALL';
      const term = searchInput ? searchInput.value.trim().toLowerCase() : '';

      const rows = document.querySelectorAll('#vulnTable tbody tr');

      rows.forEach(row => {
        const rowSev = (row.getAttribute('data-severity') || '').toUpperCase();
        const rowSrc = (row.getAttribute('data-source') || 'OTHER').toUpperCase();
        const text = row.textContent ? row.textContent.toLowerCase() : '';

        let sevOk = (sevValue === 'ALL' || rowSev === sevValue.toUpperCase());
        let srcOk = true;
        if (srcValue === 'TRIVY_ONLY') srcOk = (rowSrc === 'TRIVY');
        else if (srcValue === 'GRYPE_ONLY') srcOk = (rowSrc === 'GRYPE');
        else if (srcValue === 'BOTH') srcOk = (rowSrc === 'BOTH');

        const textOk = !term || text.indexOf(term) !== -1;
        row.style.display = (sevOk && srcOk && textOk) ? '' : 'none';
      });
    }

    function filterSecrets() {
      const sevSelect = document.getElementById('secretsSeverityFilter');
      const srcSelect = document.getElementById('secretsSourceFilter');
      const sevValue = sevSelect ? sevSelect.value : 'ALL';
      const srcValue = srcSelect ? srcSelect.value : 'ALL';
      const rows = document.querySelectorAll('#secretsTable tbody tr');

      rows.forEach(row => {
        const rowSev = row.getAttribute('data-severity') || '';
        const rowSrc = row.getAttribute('data-source') || '';
        const sevOk = (sevValue === 'ALL' || rowSev === sevValue);
        const srcOk = (srcValue === 'ALL' || rowSrc === srcValue);
        row.style.display = (sevOk && srcOk) ? '' : 'none';
      });
    }

    // --- LOGICA TOP N PACKAGES (Frontend Rank-based) ---
    const allCriticalPackages = {{ all_critical_packages_json | safe }};

    function updateTopPackages() {
        const input = document.getElementById('topNInput');
        const checkbox = document.getElementById('showAllCheck');
        if (!input || !checkbox) return;

        const tbody = document.getElementById('topPackagesBody');
        tbody.innerHTML = ''; // Clear current

        if (allCriticalPackages.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="muted">Nessun pacchetto critico trovato.</td></tr>';
            return;
        }

        let filtered = [];

        // Se "Tutti" è selezionato, ignora l'input numerico
        if (checkbox.checked) {
            filtered = allCriticalPackages;
            input.disabled = true;
            input.style.opacity = '0.5';
        } else {
            input.disabled = false;
            input.style.opacity = '1';

            let n = parseInt(input.value, 10);
            if (isNaN(n) || n < 1) n = 1; // Fallback minimo a 1

            // 1. Estrai tutti i conteggi unici ordinati
            const counts = allCriticalPackages.map(p => p.count);
            const uniqueCounts = [...new Set(counts)].sort((a, b) => b - a);

            // 2. Prendi solo i primi N conteggi
            const targetCounts = uniqueCounts.slice(0, n);

            // 3. Filtra
            filtered = allCriticalPackages.filter(p => targetCounts.includes(p.count));
        }

        let currentRank = 0;
        let lastCount = -1;

        // Render rows
        filtered.forEach(pkg => {
            // Calcolo del Rank: incrementa solo se il count cambia
            if (pkg.count !== lastCount) {
                currentRank++;
                lastCount = pkg.count;
            }

            const tr = document.createElement('tr');

            // 1. Colonna LIVELLO
            const tdRank = document.createElement('td');
            tdRank.textContent = '#' + currentRank;
            tdRank.style.textAlign = 'center';
            tdRank.style.color = '#555';

            // 2. Colonna NOME
            const tdName = document.createElement('td');
            tdName.textContent = pkg.name;

            // 3. Colonna CONTEGGIO
            const tdCount = document.createElement('td');
            tdCount.textContent = pkg.count;
            tdCount.style.color = '#b71c1c';
            tdCount.style.fontWeight = 'bold';

            tr.appendChild(tdRank);
            tr.appendChild(tdName);
            tr.appendChild(tdCount);
            tbody.appendChild(tr);
        });
    }

    window.addEventListener('DOMContentLoaded', () => {
        updateTopPackages();
    });
  </script>
</head>
<body>

<h1>Container Security Report</h1>
<p class="muted">
  Image: <code>{{ image_name }}</code>  |
  Safe name: <code>{{ safe_name }}</code>
  {% if platform %} | Platform: <code>{{ platform }}</code> {% endif %}
</p>

<div class="section">
  <h2>Executive Summary</h2>
  <ul>
    <li>
      <strong>Vulnerabilities:</strong>
      {% if vulns.missing %}
        <span class="badge">NON TROVATO</span> Nessuna vulnerabilità individuata.
      {% elif vulns.stats.total == 0 %}
        nessuna rilevata.
      {% else %}
        <span class="counter">{{ vulns.stats.total }}</span>
        {% if vulns.stats.by_severity %}
          – distribuzione per severità:
          {% for sev, count in vulns.stats.by_severity.items() %}
            <span class="badge">{{ sev }}: {{ count }}</span>
          {% endfor %}
        {% endif %}
      {% endif %}
    </li>
    <li>
      <strong>Config issues:</strong>
      {% if config.missing %}
        <span class="badge">NON TROVATO</span> Nessun dato disponibile.
      {% elif config.stats.total == 0 %}
        nessun problema rilevato.
      {% else %}
        <span class="counter">{{ config.stats.total }}</span>
        {% if config.stats.by_severity %}
          – distribuzione per severità:
          {% for sev, count in config.stats.by_severity.items() %}
            <span class="badge">{{ sev }}: {{ count }}</span>
          {% endfor %}
        {% endif %}
      {% endif %}
    </li>
    <li>
      <strong>Secrets:</strong>
      {% if secrets.missing %}
        <span class="badge">NON TROVATO</span> Nessun dato disponibile.
      {% elif secrets.stats.total == 0 %}
        nessun secret rilevato.
      {% else %}
        <span class="counter">{{ secrets.stats.total }}</span>
        {% if secrets.stats.by_severity %}
          – distribuzione per severità:
          {% for sev, count in secrets.stats.by_severity.items() %}
            <span class="badge">{{ sev }}: {{ count }}</span>
          {% endfor %}
        {% endif %}
      {% endif %}
    </li>
  </ul>
</div>

<div class="section">
  <h2>Vulnerabilities</h2>
  {% if vulns.missing %}
    <p><span class="badge">NON TROVATO</span> Nessuna vulnerabilità individuata.</p>
  {% elif vulns.stats.total == 0 %}
    <p>Nessuna vulnerabilità rilevata nel report fornito.</p>
  {% else %}
    <p class="small">
      Totale: <strong>{{ vulns.stats.total }}</strong>
      {% if vulns.stats.by_severity %}
        –
        {% for sev, count in vulns.stats.by_severity.items() %}
          <span class="badge">{{ sev }}: {{ count }}</span>
        {% endfor %}
      {% endif %}
    </p>

    {% if vulns.coverage %}
      <p class="small">
        Scanner coverage:
        Only Trivy: {{ vulns.coverage.trivy_only | default(0) }},
        Only Grype: {{ vulns.coverage.grype_only | default(0) }},
        Both: {{ vulns.coverage.both | default(0) }}
      </p>
    {% endif %}

    <div class="small" style="margin-bottom: 0.75rem;">
      <h3 style="margin:0.4rem 0 0.5rem 0;">Distribuzione per severità</h3>
      <table class="layout-grid">
        <tr>
          <td class="col-narrow">{{ severity_pie_data.svg|safe }}</td>
          <td>{{ severity_pie_data.legend|safe }}</td>
        </tr>
      </table>

      <h3 style="margin:0.9rem 0 0.5rem 0;">Analisi Pacchetti: Istogramma e Distribuzione</h3>
      <table class="layout-grid">
        <tr>
          <td class="col-chart-svg">{{ pkg_histogram_svg|safe }}</td>
          <td class="col-chart-pie">{{ pkg_pie_data.svg|safe }}</td>
        </tr>
      </table>

      <h3 style="margin:0.5rem 0 0.5rem 0;">Dettaglio Pacchetti</h3>
      <div style="margin-top: 0;">{{ pkg_pie_data.legend|safe }}</div>
    </div>

    {% if not for_pdf %}
      {# --- TOP N CRITICAL PACKAGES SECTION (HTML ONLY) --- #}
      {% if all_critical_packages_json != "[]" %}
        <div style="margin-top: 1.5rem; margin-bottom: 1.5rem; background-color: #fffafaf0; border: 1px dashed #e57373; padding: 10px;">
          <h3 style="color: #b71c1c; margin-top: 0; display: flex; align-items: center;">
            Top Critical Packages

            <span style="font-size: 0.9rem; font-weight: normal; margin-left: 15px; color: #555; display: flex; align-items: center;">
                <label style="margin-right: 5px;">Mostra primi (Rank):</label>
                <input type="number" id="topNInput" value="5" min="1"
                       style="width: 50px; padding: 2px; text-align: center; margin-right: 15px;"
                       oninput="updateTopPackages()">

                <label style="cursor: pointer; user-select: none;">
                    <input type="checkbox" id="showAllCheck" onchange="updateTopPackages()"> Tutti
                </label>
            </span>
          </h3>
          <p class="small muted">
            Pacchetti con il maggior numero di vulnerabilità CRITICAL. <br>
            Nota: La selezione numerica mostra i primi N livelli di gravità (include i pareggi).
          </p>
          <table class="top-packages-table" style="width: auto; min-width: 50%;">
            <thead>
              <tr>
                <th style="width: 80px; text-align: center;">Livello</th>
                <th>Package Name</th>
                <th>Critical Count</th>
              </tr>
            </thead>
            <tbody id="topPackagesBody">
              </tbody>
          </table>
        </div>
      {% endif %}

      {# --- FILTERS AND SEARCH SECTION --- #}
      <div class="small" style="margin-bottom: 0.75rem; border-top: 1px solid #eee; padding-top: 10px;">
        <label for="vulnFilter">Filtra per severità:</label>
        <select id="vulnFilter" onchange="filterVulns()">
          <option value="ALL">(tutte)</option>
          {% for sev in ["CRITICAL","HIGH","MEDIUM","LOW","NEGLIGIBLE","UNKNOWN","INFO","UNDEFINED"] %}
            {% if sev in vulns.stats.by_severity %}
              <option value="{{ sev }}">{{ sev }}</option>
            {% endif %}
          {% endfor %}
        </select>
        <span style="margin-left: 1rem;"></span>
        <label for="vulnSourceFilter">Filtra per fonte:</label>
        <select id="vulnSourceFilter" onchange="filterVulns()">
          <option value="ALL">(tutte)</option>
          <option value="TRIVY_ONLY">Solo Trivy</option>
          <option value="GRYPE_ONLY">Solo Grype</option>
          <option value="BOTH">Entrambe</option>
        </select>
        <span style="margin-left: 1rem;"></span>
        <label for="vulnSearch">Cerca:</label>
        <input id="vulnSearch" type="text" placeholder="es. php, apache2, CVE-2023-..." oninput="filterVulns()" />
      </div>
    {% endif %}

    <table id="vulnTable">
      <thead>
        <tr>
          <th>CVE / ID</th>
          <th>Package</th>
          <th>Installed</th>
          <th>Severity</th>
          <th>CVSS</th>
          <th>Fixed in</th>
          <th>Refs/Exploits</th>
          <th>Source</th>
        </tr>
      </thead>
      <tbody>
        {% for v in vulns["items"] %}
          {% set sev = (v.severity or "UNKNOWN").upper() %}
          {% set src = (v.source or "") %}
          {% set src_u = src.upper() %}
          {% if "TRIVY" in src_u and "GRYPE" in src_u %}
            {% set src_tag = "BOTH" %}
          {% elif "TRIVY" in src_u %}
            {% set src_tag = "TRIVY" %}
          {% elif "GRYPE" in src_u %}
            {% set src_tag = "GRYPE" %}
          {% else %}
            {% set src_tag = "OTHER" %}
          {% endif %}
          <tr data-severity="{{ sev }}" data-source="{{ src_tag }}">
            <td><code>{{ v.id }}</code></td>
            <td>{{ v.package }}</td>
            <td>{{ v.installed }}</td>
            <td><span class="pill sev-{{ sev }}">{{ sev }}</span></td>
            <td>{{ v.cvss }}</td>
            <td>{{ v.fixed }}</td>
            <td>
              {% set vid = v.id or "" %}
              {% if vid %}
                <a href="https://nvd.nist.gov/vuln/detail/{{ vid|e }}" target="_blank" style="font-weight:bold; text-decoration:none; color:#1976d2;">NVD</a>
                <br>

                {# --- SHOW VERIFIED LINKS (WITH ORIGIN DISTINCTION) --- #}
                {% if v.verified_links %}
                    <span style="font-size: 0.75rem; color: #666;">Exploit:</span><br>
                    {% for link in v.verified_links %}

                        {# DIFFERENT STYLE IF IT COMES FROM CISA, CSV (EDB) OR SCANNER #}
                        {% if link.origin == 'cisa' %}
                            <a href="{{ link.url }}" target="_blank" style="color:#b71c1c; font-weight:900; background-color:#ffcdd2; padding:2px 5px; border-radius:4px; border:1px solid #e57373; text-decoration:none; white-space: nowrap; font-size:0.8rem;" title="Vulnerabilità attivamente sfruttata (CISA KEV)">
                              CISA KEV
                            </a><br>
                        {% elif link.origin == 'csv' %}
                            <a href="{{ link.url }}" target="_blank" style="color:#bf360c; font-weight:bold; white-space: nowrap;" title="Exploit trovato nel DB locale (CSV)">
                              EDB (CSV)
                            </a><br>
                        {% else %}
                            <a href="{{ link.url }}" target="_blank" style="color:#d32f2f; font-weight:900; white-space: nowrap;" title="Exploit verificato da Scanner">
                              {{ link.label }}
                            </a><br>
                        {% endif %}

                    {% endfor %}

                {# --- FALLBACK OPTION 1: GOOGLE DORK (Broad) --- #}
                {% else %}
                    <a href="https://www.google.com/search?q={{ vid|e }}+exploit+OR+poc" target="_blank" style="color:#777; font-size: 0.75rem; text-decoration: none;" title="Cerca PoC o discussioni su Google">
                      🔍 Web Search
                    </a>
                {% endif %}

              {% else %} - {% endif %}
            </td>
            <td>{{ v.source }}</td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  {% endif %}
</div>

<div class="section">
  <h2>Configuration Issues</h2>
  {% if config.missing %}
    <p><span class="badge">NON TROVATO</span> Nessun dato disponibile.</p>
  {% elif config.stats.total == 0 %}
    <p>Nessun problema di configurazione rilevato.</p>
  {% else %}
    <p class="small">
      Totale: <strong>{{ config.stats.total }}</strong>
      {% if config.stats.by_severity %}
        –
        {% for sev, count in config.stats.by_severity.items() %}
          <span class="badge">{{ sev }}: {{ count }}</span>
        {% endfor %}
      {% endif %}
    </p>

    {% if not for_pdf and config.stats.by_severity %}
      <div class="small" style="margin-bottom: 0.75rem;">
        <label for="configFilter">Filtra per severità:</label>
        <select id="configFilter" onchange="filterBySeverity('configFilter','configTable')">
          <option value="ALL">(tutte)</option>
          {% for sev, count in config.stats.by_severity.items() %}
            <option value="{{ sev }}">{{ sev }}</option>
          {% endfor %}
        </select>
      </div>
    {% endif %}

    {% if config.dive %}
      <h3>Efficienza immagine (Dive)</h3>
      <ul class="small">
        {% if config.dive.efficiency_score is not none %} <li>Efficiency score: {{ config.dive.efficiency_score }}</li> {% endif %}
        {% if config.dive.wasted_bytes_h is not none %} <li>Wasted bytes: ~{{ config.dive.wasted_bytes_h }}</li> {% endif %}
      </ul>
    {% endif %}

    <table id="configTable">
      <thead>
        <tr>
          <th>ID</th>
          <th>Severity</th>
          <th>Description</th>
          <th>Hint</th>
        </tr>
      </thead>
      <tbody>
        {% for f in config.findings %}
          {% set sev = (f.severity or "Unknown") %}
          {% set sev_u = sev.upper() %}
          <tr data-severity="{{ sev }}">
            <td><code>{{ f.id }}</code></td>
            <td><span class="pill sev-{{ sev_u }}">{{ sev }}</span></td>
            <td>{{ f.description }}</td>
            <td>{{ f.hint }}</td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  {% endif %}
</div>

<div class="section">
  <h2>Secrets</h2>
  {% if secrets.missing %}
    <p><span class="badge">NON TROVATO</span> Nessun dato disponibile.</p>
  {% elif secrets.stats.total == 0 %}
    <p>Nessun secret rilevato nei dati forniti.</p>
  {% else %}
    <p class="small">
      Totale: <strong>{{ secrets.stats.total }}</strong>
      {% if secrets.stats.by_severity %}
        –
        {% for sev, count in secrets.stats.by_severity.items() %}
          <span class="badge">{{ sev }}: {{ count }}</span>
        {% endfor %}
      {% endif %}
    </p>

    {% if secrets.stats.by_rule %}
      <p class="small">Rule summary:</p>
      <ul class="small">
        {% for rule, count in secrets.stats.by_rule.items() %}
          <li><code>{{ rule }}</code>: {{ count }}</li>
        {% endfor %}
      </ul>
    {% endif %}

    {% if not for_pdf %}
      <div class="small" style="margin-bottom: 0.75rem;">
        <label for="secretsSeverityFilter">Filtra per severità:</label>
        <select id="secretsSeverityFilter" onchange="filterSecrets()">
          <option value="ALL">(tutte)</option>
          {% for sev, count in secrets.stats.by_severity.items() %}
            <option value="{{ sev }}">{{ sev }}</option>
          {% endfor %}
        </select>
        <span style="margin-left: 1rem;"></span>
        <label for="secretsSourceFilter">Filtra per fonte:</label>
        <select id="secretsSourceFilter" onchange="filterSecrets()">
          <option value="ALL">(tutte)</option>
          {% for t, count in secrets.stats.by_type.items() %}
            <option value="{{ t }}">{{ t }}</option>
          {% endfor %}
        </select>
      </div>
    {% endif %}

    {% if secrets.common_prefix %}
      <p class="small muted">
        Prefisso di path comune (tronco):<br>
        <code class="prefix-path">{{ secrets.common_prefix }}</code>
      </p>
    {% endif %}

    <table id="secretsTable">
      <colgroup>
        <col width="10%"> <col width="12%"> <col width="9%"> <col width="32%"> <col width="6%"> <col width="9%"> <col width="30%">
      </colgroup>
      <thead>
        <tr>
          <th>Type</th> <th>Rule</th> <th>Severity</th> <th>File</th> <th>Line</th> <th>Entropy</th> <th>Snippet</th>
        </tr>
      </thead>
      <tbody>
        {% for s in secrets.findings %}
          {% set sev = s.severity or "Unknown" %}
          {% set sev_u = sev.upper() %}
          <tr data-severity="{{ s.severity }}" data-source="{{ s.type }}">
            <td>{{ s.type }}</td>
            <td>{{ s.rule_id }}</td>
            <td><span class="pill sev-{{ sev_u }}">{{ sev }}</span></td>
            <td>{{ s.display_file_path }}</td>
            <td>{{ s.line_number }}</td>
            <td>{% if s.entropy is not none %}{{ "%.2f"|format(s.entropy) }}{% else %}-{% endif %}</td>
            <td><code>{{ s.match | safe }}</code></td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  {% endif %}
</div>

</body>
</html>
"""


def _build_jinja_env() -> Environment:
    env = Environment(
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["chunkwrap"] = _chunk_wrap
    env.filters["insert_wbr"] = _insert_wbr_breaks
    return env


def render_html_report(context: Dict[str, Any]) -> str:
    env = _build_jinja_env()
    template = env.from_string(_HTML_TEMPLATE)
    return template.render(**context)


# ---------------------------------------------------------------------------
# PDF Generation
# ---------------------------------------------------------------------------

def generate_pdf_from_html(html: str, pdf_path: Path) -> None:
    wk = shutil.which("wkhtmltopdf")
    if wk is None:
        print("[Module 5] WARNING: wkhtmltopdf not found. PDF not generated.")
        return

    cmd = [
        wk,
        "--encoding", "utf-8",
        "--enable-local-file-access",
        "--print-media-type",
        "--enable-javascript",
        "--javascript-delay", "2000",
        "-",
        str(pdf_path),
    ]
    print(f"[Module 5] Running wkhtmltopdf...")
    proc = subprocess.run(
        cmd,
        input=html.encode("utf-8"),
        text=False,
        capture_output=True,
    )
    if proc.returncode == 0:
        print(f"[Module 5] PDF written in: {pdf_path}")
    else:
        print(f"[Module 5] wkhtmltopdf ERROR (rc={proc.returncode}): {proc.stderr.strip()}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _load_json_optional(path: Path, label: str) -> Tuple[Optional[Dict[str, Any]], bool]:
    """
    Loads JSON if it exists. If it's missing or unreadable, it does NOT raise an exception:
    returns (None, True) and prints a warning.
    """
    if not path.is_file():
        print(f"[Module5] WARNING: {label} JSON not found: {path}")
        return None, True

    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f), False
    except Exception as e:
        print(f"[Module5] WARNING: Unable to read {label} JSON ({path}): {e}")
        return None, True


def _first_nonempty_str(*vals: Any) -> str:
    for v in vals:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def run_module5(
    vulns_json: Path,
    config_json: Path,
    secrets_json: Path,
) -> None:
    # Resilient loading: no crashes if an input is missing
    vulns_data, vulns_missing = _load_json_optional(vulns_json, "Vuln")
    config_data, config_missing = _load_json_optional(config_json, "Config")
    secrets_data, secrets_missing = _load_json_optional(secrets_json, "Secrets")

    # --- EXTERNAL DATABASE SETUP ---
    # (Only needed if we have vulnerability data; otherwise, there's no point in downloading/mapping them)
    edb_map: Dict[str, str] = {}
    cisa_map: Dict[str, str] = {}
    if not vulns_missing:
        script_dir = Path(__file__).parent.resolve()
        edb_csv_path = script_dir / "files_exploits.csv"
        cisa_json_path = script_dir / "cisa_kev.json"

        # Automatic download (if older than 24 hours, otherwise uses cache. If it fails, it warns but doesn't crash)
        ensure_edb_database(edb_csv_path)
        ensure_cisa_database(cisa_json_path)

        # Loading Maps
        edb_map = load_edb_cve_map(edb_csv_path)
        cisa_map = load_cisa_cve_map(cisa_json_path)

    # Robust metadata (take where available)
    image_name = _first_nonempty_str(
        (vulns_data or {}).get("image"),
        (config_data or {}).get("image"),
        (secrets_data or {}).get("image"),
        (secrets_data or {}).get("image_name"),
        (secrets_data or {}).get("image_safe_name"),
    )

    safe_name = _first_nonempty_str(
        (vulns_data or {}).get("safe_name"),
        (config_data or {}).get("safe_name"),
        (secrets_data or {}).get("safe_name"),
        (secrets_data or {}).get("image_safe_name"),
    )
    if not safe_name:
        # Deterministic fallback even if files are missing: use the stem of a passed path
        safe_name = _first_nonempty_str(vulns_json.stem, config_json.stem, secrets_json.stem, "unknown")

    platform = (vulns_data or {}).get("platform") or (config_data or {}).get("platform") or (secrets_data or {}).get("platform")

    outputs_root = Path("outputs")
    report_dir = outputs_root / "report" / safe_name
    report_dir.mkdir(parents=True, exist_ok=True)

    print(f"[Module5] Generate report in: {report_dir}")

    # Normalization: if given None -> empty (already handled by functions)
    vulns_norm = _normalize_vulns(vulns_data, edb_map, cisa_map)
    config_norm = _normalize_config(config_data)
    secrets_norm = _normalize_secrets(secrets_data)

    # Template flag: Displays "NOT FOUND" ONLY if the file is missing,
    # leaving the "0 findings" logic unchanged when the file exists but is empty.
    vulns_norm["missing"] = bool(vulns_missing)
    config_norm["missing"] = bool(config_missing)
    secrets_norm["missing"] = bool(secrets_missing)

    # Graphs
    sev_map = vulns_norm.get("stats", {}).get("by_severity", {}) or {}
    pkg_counts: Dict[str, int] = {}
    for item in vulns_norm.get("items", []):
        pkg = item.get("package") or "(unknown)"
        pkg_counts[pkg] = pkg_counts.get(pkg, 0) + 1
    pkg_sorted = sorted(pkg_counts.items(), key=lambda x: x[1], reverse=True)

    # Graphic Data
    pkg_pie_data = svg_package_pie(pkg_sorted)
    severity_pie_data = svg_pie_chart(sev_map)
    pkg_histogram_svg = svg_histogram(pkg_sorted, max_bars=10)

    # DATA FOR TOP N (Frontend): We extract ALL sorted critics
    all_critical_packages_list = get_all_critical_packages(vulns_norm["items"])
    # Let's convert it to JSON string to inject it into JS
    all_critical_json = json.dumps(all_critical_packages_list)

    context = {
        "image_name": image_name,
        "safe_name": safe_name,
        "platform": platform,
        "vulns": vulns_norm,
        "config": config_norm,
        "secrets": secrets_norm,
        # Graphical structured data
        "severity_pie_data": severity_pie_data,
        "pkg_pie_data": pkg_pie_data,
        "pkg_histogram_svg": pkg_histogram_svg,
        # Top N Data (JS Complete)
        "all_critical_packages_json": all_critical_json,
        "for_pdf": False,
    }

    # HTML (with filters and dynamic Top N table)
    html = render_html_report(context)
    html_path = report_dir / "report.html"
    html_path.write_text(html, encoding="utf-8")
    print(f"[Module5] HTML written in: {html_path}")

    # PDF (WITHOUT filters and WITHOUT Top N table)
    context_pdf = dict(context)
    context_pdf["for_pdf"] = True
    html_for_pdf = render_html_report(context_pdf)
    pdf_path = report_dir / "report.pdf"
    generate_pdf_from_html(html_for_pdf, pdf_path)

    # JSON Summary
    summary = {
        "image": image_name,
        "safe_name": safe_name,
        "platform": platform,
        "vulnerabilities": vulns_norm.get("stats", {}),
        "config_issues": config_norm.get("stats", {}),
        "secrets": secrets_norm.get("stats", {}),
        "missing_inputs": {
            "vulnerabilities": bool(vulns_missing),
            "misconfigurations": bool(config_missing),
            "secrets": bool(secrets_missing),
        }
    }
    summary_path = report_dir / "report_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[Module5] Summary JSON written in: {summary_path}")


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Module 5 – HTML/PDF report")
    parser.add_argument("--vulns-json", type=Path, required=True, help="Path to the vulnerability summary JSON (Module 2)")
    parser.add_argument("--config-json", type=Path, required=True, help="Path to config issues JSON (Module 3)")
    parser.add_argument("--secrets-json", type=Path, required=True, help="Path to secrets JSON (Module 4)")

    args = parser.parse_args(argv)
    run_module5(
        vulns_json=args.vulns_json,
        config_json=args.config_json,
        secrets_json=args.secrets_json,
    )


if __name__ == "__main__":
    main()
