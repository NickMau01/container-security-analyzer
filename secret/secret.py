from __future__ import annotations

"""
Module 4 – Secret Detector (regex + entropy + TruffleHog/Gitleaks)

- Scans the rootfs (unpacked) of an image.
- Searches for secrets with:
    * custom regex (AWS, JWT, private keys, passwords, DB, tokens, etc.)
    * entropy on high randomness tokens
    * TruffleHog (filesystem --json)
    * Gitleaks (detect --no-git --report-format=json)
- Ignores:
    * system directories (e.g., /usr, /var, /proc, ...)
    * binary files (also by extension, e.g., .so, .dll, .exe, .jar, ...)
"""

import argparse
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

# Base directory where the reports will be saved (JSON + Markdown)
OUT_BASE_DIR = "outputs/secrets"

# Global parameters for entropy analysis
MIN_ENTROPY_LENGTH = 20       # minimum length of token to consider
MIN_ENTROPY_VALUE = 4.8       # minimum entropy threshold for marking a finding

# Names (or paths) of external binaries, assuming they are in the PATH
TRUFFLEHOG_BIN = "trufflehog"
GITLEAKS_BIN = "gitleaks"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SecretFinding:
    """
    Represents a single "secret" found by the system,
    regardless of the source (regex, entropy, TruffleHog, Gitleaks).
    """
    type: str          # source: "regex", "entropy", "trufflehog", "gitleaks", ...
    rule_id: str       # rule identifier (e.g., AWS_ACCESS_KEY_ID)
    description: str   # human-readable description of the rule
    file_path: str     # file path where the secret was found
    line_number: int   # line number (if available, 0 otherwise)
    match: str         # string that triggered the rule
    entropy: float     # entropy (only for "entropy" type findings)
    severity: str      # "Low" | "Medium" | "High" | "Unknown"

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

def normalize_severity(raw: Optional[str], default: str = "Unknown") -> str:
    """
    Normalizes severity values into the Low/Medium/High/Unknown schema.

    Important note:
    - Many tools (e.g., TruffleHog/Gitleaks) often DO NOT provide a reliable/standard severity
      or leave it empty.
    - To avoid artificially forcing "Medium", the default is "Unknown".
    """
    if raw is None:
        return default
    s = str(raw).strip().lower()
    if not s:
        return default

    if s in {"critical", "crit"}:
        return "High"
    if s in {"high"}:
        return "High"
    if s in {"medium", "med"}:
        return "Medium"
    if s in {"low"}:
        return "Low"
    if s in {"info", "informational"}:
        return "Low"

    # Any unrecognized value -> Unknown (or passed default)
    return default


# ---------------------------------------------------------------------------
# Regex rules
# ---------------------------------------------------------------------------

BUILTIN_REGEX_RULES: Dict[str, Dict[str, str]] = {
    # AWS
    "Aws_Access_Key_ID": {
        "pattern": r"(?i)AKIA[0-9A-Z]{16}",
        "description": "Possible AWS Access Key ID",
        "severity": "High",
    },
    "Aws_Secret_Access_Key": {
        "pattern": r"(?i)aws_secret_access_key\s*[:=]\s*([0-9A-Za-z/+=]{40})",
        "description": "Possible AWS Secret Access Key",
        "severity": "High",
    },

    # Generic API / OAuth token
    "Generic_API_Key": {
        "pattern": r"(?i)(api[_-]?key|token)\s*[:=]\s*['\"]?[0-9A-Za-z\-_=]{20,}['\"]?",
        "description": "Generic API key / token-like string",
        "severity": "Medium",
    },

    # JWT
    "Jwt_Token": {
        "pattern": r"eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+",
        "description": "Possible JWT token",
        "severity": "Medium",
    },

    # Private keys (PEM)
    "Private_Key_Block": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "description": "Possible private key block",
        "severity": "High",
    },

    # Hardcoded passwords (also DB)
    "Password_Assignment": {
        "pattern": r"(?i)(password|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
        "description": "Possible hardcoded password",
        "severity": "High",
    },

    # DB connection strings
    "DB_Connection_String": {
        "pattern": r"(?i)(jdbc:|postgresql://|mysql://|mongodb://)[^\s]+",
        "description": "Possible DB connection string",
        "severity": "Medium",
    },

    # GitHub token
    "GitHub_Token": {
        "pattern": r"ghp_[0-9A-Za-z]{36}",
        "description": "Possible GitHub Personal Access Token",
        "severity": "High",
    },
}


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """
    Calculates the Shannon entropy of a string, in bits per symbol.
    The higher the value, the more "random" the string seems.
    """
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    if length == 0:
        return 0.0
    from math import log2
    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * log2(p)
    return ent


def sliding_window_tokens(line: str, window_size: int) -> Iterable[str]:
    """
    Splits a line into "tokens" separated by non-alphanumeric characters,
    and returns only those with length at least window_size.
    """
    if not line:
        return []
    tokens = re.split(r"[^0-9A-Za-z_\-=]+", line)
    for tok in tokens:
        tok = tok.strip()
        if len(tok) >= window_size:
            yield tok


# ---------------------------------------------------------------------------
# Path / Binary exclusion heuristics
# ---------------------------------------------------------------------------

SKIP_DIRS_NAME = {
    "proc",
    "sys",
    "dev",
    "run",
    "tmp",
    "var",
    "usr",
    "lib",
    "lib64",
    "boot",
    "bin",
    "sbin",
}

BINARY_EXTENSIONS = {
    ".so",
    ".dll",
    ".exe",
    ".bin",
    ".o",
    ".a",
    ".pyc",
    ".class",
    ".jar",
}

ENTROPY_SKIP_EXTENSIONS = {
    ".pem",
    ".crt",
    ".cer",
    ".der",
    ".p7b",
    ".p7c",
    ".pfx",
    ".p12",
    ".jar",
    ".war",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".mp3",
    ".mp4",
    ".ogg",
    ".pdf",
}


def should_skip_dir(path: Path, rootfs_dir: Path) -> bool:
    """
     Returns True if the directory should be completely ignored.

    Exceptions:
    - does not skip /var/www
    - does not skip /var/app
    """
    try:
        rel = path.relative_to(rootfs_dir)
    except ValueError:
        return False

    parts = rel.parts
    if not parts:
        return False

    first = parts[0]

    if first == "var":
        if len(parts) >= 2 and parts[1] in {"www", "app"}:
            return False
        return True

    return first in SKIP_DIRS_NAME


def is_probably_binary(path: Path, sample_size: int = 4096) -> bool:
    """
    Estimates if a file is binary.
    """
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True

    try:
        with path.open("rb") as fh:
            chunk = fh.read(sample_size)
    except (OSError, IOError):
        return True

    if not chunk:
        return False

    if b"\x00" in chunk:
        return True

    nontext = 0
    for b in chunk:
        if b in (9, 10, 13):
            continue
        if 32 <= b <= 126:
            continue
        nontext += 1

    ratio = nontext / len(chunk)
    return ratio > 0.30


def iter_text_files(rootfs_dir: Path) -> Iterable[Path]:
    """
    Iterates through all text-like files in the rootfs.
    """
    for dirpath, dirnames, filenames in os.walk(rootfs_dir):
        current_dir = Path(dirpath)

        if should_skip_dir(current_dir, rootfs_dir):
            dirnames[:] = []
            continue

        for filename in filenames:
            p = current_dir / filename
            if is_probably_binary(p):
                continue
            yield p


# ---------------------------------------------------------------------------
# Path filters for ENTROPY
# ---------------------------------------------------------------------------

def _is_entropy_allowed_path(path: Path, rootfs_dir: Path) -> bool:
    """
    Decides if entropy analysis makes sense for a particular file.
    """
    try:
        rel = path.relative_to(rootfs_dir)
    except ValueError:
        return False

    parts = rel.parts
    if not parts:
        return False

    first = parts[0]

    if first == "usr":
        return False

    if first in {"app", "srv", "opt", "home", "root"}:
        return True

    if first == "var":
        if len(parts) >= 2 and parts[1] in {"www", "app"}:
            return True
        return False

    if first == "etc":
        if len(parts) >= 2 and parts[1] in {"ssl", "pki", "apt"}:
            return False
        return True

    return False


def _read_file_safely(path: Path) -> Optional[str]:
    """
    Reads the entire file as text.
    """
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except (OSError, IOError):
        return None


def analyze_file_with_entropy(
    path: Path,
    min_length: int,
    min_entropy_value: float,
    rootfs_dir: Path,
) -> List[SecretFinding]:
    """
    Analyzes a single file with the entropy algorithm.
    """
    findings: List[SecretFinding] = []

    if not _is_entropy_allowed_path(path, rootfs_dir):
        return findings

    if path.suffix.lower() in ENTROPY_SKIP_EXTENSIONS:
        return findings

    text = _read_file_safely(path)
    if text is None:
        return findings

    lines = text.splitlines()
    for line_no, line in enumerate(lines, start=1):
        for token in sliding_window_tokens(line, window_size=min_length):
            ent = shannon_entropy(token)
            if ent >= min_entropy_value:
                findings.append(
                    SecretFinding(
                        type="entropy",
                        rule_id="HIGH_ENTROPY",
                        description="High-entropy token (possible secret)",
                        file_path=str(path),
                        line_number=line_no,
                        match=token,
                        entropy=ent,
                        severity="Medium",  # conservative choice (remains unchanged)
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Scan rootfs – regex + entropy
# ---------------------------------------------------------------------------

def scan_rootfs_for_secrets(
    rootfs_dir: Path,
    regex_rules: Optional[Dict[str, Dict[str, str]]] = None,
    min_entropy_length: int = MIN_ENTROPY_LENGTH,
    min_entropy_value: float = MIN_ENTROPY_VALUE,
) -> List[SecretFinding]:
    """
    Main "internal" engine (without external tools).
    """
    if regex_rules is None:
        regex_rules = BUILTIN_REGEX_RULES

    compiled_rules: List[Tuple[str, re.Pattern, str, str]] = []
    for rule_id, meta in regex_rules.items():
        pattern = meta.get("pattern")
        if not pattern:
            continue
        desc = meta.get("description", rule_id)
        sev = meta.get("severity", "Medium")
        try:
            regex = re.compile(pattern)
        except re.error:
            print(f"[WARN] Invalid regex for rule {rule_id}, skipping", file=sys.stderr)
            continue
        compiled_rules.append((rule_id, regex, desc, sev))

    findings: List[SecretFinding] = []

    for path in iter_text_files(rootfs_dir):
        text = _read_file_safely(path)
        if text is None:
            continue

        lines = text.splitlines()
        for line_no, line in enumerate(lines, start=1):
            for rule_id, regex, desc, sev in compiled_rules:
                for m in regex.finditer(line):
                    match_str = m.group(0)
                    findings.append(
                        SecretFinding(
                            type="regex",
                            rule_id=rule_id,
                            description=desc,
                            file_path=str(path),
                            line_number=line_no,
                            match=match_str,
                            entropy=0.0,
                            severity=sev,
                        )
                    )

        findings.extend(
            analyze_file_with_entropy(
                path=path,
                min_length=min_entropy_length,
                min_entropy_value=min_entropy_value,
                rootfs_dir=rootfs_dir,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# TruffleHog integration
# ---------------------------------------------------------------------------

def run_trufflehog_on_rootfs(
    rootfs_dir: Path,
    executable: str = TRUFFLEHOG_BIN,
) -> List[SecretFinding]:
    """
    Runs TruffleHog and converts the JSON results into SecretFinding.
    """
    import subprocess

    findings: List[SecretFinding] = []

    cmd = [
        executable,
        "filesystem",
        "--json",
        str(rootfs_dir),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        print(
            f"[WARN] trufflehog not found in PATH (command: {executable}). "
            "Skipping TruffleHog integration.",
            file=sys.stderr,
        )
        return findings

    if proc.returncode not in (0, 1):
        print(
            f"[WARN] trufflehog exited with code {proc.returncode}. "
            "Attempting to parse the output.",
            file=sys.stderr,
        )

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        detector = obj.get("DetectorName") or "TRUFFLEHOG"
        raw = obj.get("Redacted") or obj.get("Raw") or ""

        # HERE: default Unknown (not Medium)
        severity = normalize_severity(obj.get("Severity"), default="Unknown")

        file_path = ""
        line_no = 0
        src_meta = obj.get("SourceMetadata", {}).get("Data", {})
        fs_meta = (
            src_meta.get("Filesystem")
            or src_meta.get("FilesystemScan")
            or {}
        )
        file_path = fs_meta.get("file") or fs_meta.get("File") or ""
        line_no = fs_meta.get("line") or fs_meta.get("Line") or 0

        findings.append(
            SecretFinding(
                type="trufflehog",
                rule_id=str(detector),
                description=f"TruffleHog: {detector}",
                file_path=str(file_path),
                line_number=int(line_no) if line_no else 0,
                match=str(raw),
                entropy=0.0,
                severity=severity,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Gitleaks integration
# ---------------------------------------------------------------------------

def run_gitleaks_on_rootfs(
    rootfs_dir: Path,
    executable: str = GITLEAKS_BIN,
) -> List[SecretFinding]:
    """
    Runs Gitleaks and converts the JSON report into SecretFinding.
    """
    import subprocess

    findings: List[SecretFinding] = []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name

    cmd = [
        executable,
        "detect",
        f"--source={rootfs_dir}",
        "--no-git",
        "--report-format=json",
        f"--report-path={report_path}",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        print(
            f"[WARN] gitleaks not found in PATH (command: {executable}). "
            "Skipping Gitleaks integration.",
            file=sys.stderr,
        )
        return findings

    if proc.returncode not in (0, 1):
        print(
            f"[WARN] gitleaks exited with code {proc.returncode}. "
            "Attempting to read the report.",
            file=sys.stderr,
        )

    try:
        with open(report_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        print(
            f"[WARN] Unable to read/parse gitleaks report ({e}).",
            file=sys.stderr,
        )
        return findings

    if isinstance(data, dict) and "leaks" in data:
        leaks = data.get("leaks") or []
    else:
        leaks = data

    if not isinstance(leaks, list):
        leaks = []

    for leak in leaks:
        if not isinstance(leak, dict):
            continue

        file_path = leak.get("File") or leak.get("file") or ""
        line_no = leak.get("StartLine") or leak.get("Line") or 0
        secret = leak.get("Secret") or leak.get("secret") or ""
        rule_id = leak.get("RuleID") or leak.get("Rule") or "GITLEAKS"
        desc = leak.get("Description") or f"Gitleaks rule {rule_id}"

        # HERE: default Unknown (not Medium)
        severity = normalize_severity(leak.get("Severity"), default="Unknown")

        findings.append(
            SecretFinding(
                type="gitleaks",
                rule_id=str(rule_id),
                description=str(desc),
                file_path=str(file_path),
                line_number=int(line_no) if line_no else 0,
                match=str(secret),
                entropy=0.0,
                severity=severity,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate_findings(findings: List[SecretFinding]) -> List[SecretFinding]:
    """
    Basic deduplication of findings.
    """
    seen = set()
    result: List[SecretFinding] = []
    for f in findings:
        key = (f.type, f.rule_id, f.file_path, f.line_number, f.match)
        if key in seen:
            continue
        seen.add(key)
        result.append(f)
    return result


# ---------------------------------------------------------------------------
# JSON / Markdown Output
# ---------------------------------------------------------------------------

def derive_safe_name_from_rootfs(rootfs_dir: Path) -> str:
    """
    Derives the "safe_name" of the image from the rootfs path.
    """
    unpacked_dir = rootfs_dir.parent
    extracted_dir = unpacked_dir.parent

    name = extracted_dir.name
    if name.startswith("extracted_"):
        return name[len("extracted_"):]
    return name or "unknown_image"


def write_json(findings: List[SecretFinding], out_dir: Path, safe_name: str) -> None:
    """
    Writes a JSON file with:
    - image name
    - total findings count
    - count by type:rule
    - count by severity
    - full findings list
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{safe_name}_secrets.json"

    counts_by_rule: Dict[str, int] = {}
    counts_by_severity: Dict[str, int] = {}

    for f in findings:
        key = f"{f.type}:{f.rule_id}"
        counts_by_rule[key] = counts_by_rule.get(key, 0) + 1
        counts_by_severity[f.severity] = counts_by_severity.get(f.severity, 0) + 1

    data = {
        "image_safe_name": safe_name,
        "total_findings": len(findings),
        "counts_by_rule": counts_by_rule,
        "counts_by_severity": counts_by_severity,
        "findings": [asdict(f) for f in findings],
    }

    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def _md_escape_cell(text: str) -> str:
    return text.replace("|", "\\|" )


def write_markdown(findings: List[SecretFinding], out_dir: Path, safe_name: str) -> None:
    """
    Writes a report in Markdown, organized by type of finding.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{safe_name}_secrets.md"

    lines: List[str] = []
    lines.append(f"# Secret Report – {safe_name}")
    lines.append("")
    lines.append(f"Totale findings: **{len(findings)}**")
    lines.append("")

    by_type: Dict[str, List[SecretFinding]] = {}
    for f in findings:
        by_type.setdefault(f.type, []).append(f)

    for t, group in sorted(by_type.items(), key=lambda x: x[0]):
        lines.append(f"## Findings da `{t}`")
        lines.append("")
        if not group:
            lines.append("_Nessun finding._")
            lines.append("")
            continue

        lines.append("| Tipo | Regola | Severità | File | Linea | Entropia | Estratto |")
        lines.append("|------|--------|----------|------|-------|----------|----------|")

        for f in group:
            tipo = _md_escape_cell(f.type)
            regola = _md_escape_cell(f.rule_id)
            sev = _md_escape_cell(f.severity)
            file_cell = _md_escape_cell(f.file_path)
            line_cell = str(f.line_number)
            ent_cell = f"{f.entropy:.2f}" if f.entropy else ""
            snippet = _md_escape_cell(f.match)

            lines.append(
                "| {tipo} | {regola} | {sev} | `{file}` | {linea} | {entropia} | `{snippet}` |".format(
                    tipo=tipo,
                    regola=regola,
                    sev=sev,
                    file=file_cell,
                    linea=line_cell,
                    entropia=ent_cell,
                    snippet=snippet,
                )
            )

        lines.append("")

    with out_path.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> None:
    ap = argparse.ArgumentParser(
        description="Module 4 – Secret Detector (regex + entropy + TruffleHog/Gitleaks)",
    )
    ap.add_argument(
        "--unpacked-dir",
        required=True,
        help="Directory 'unpacked' from the bundle (the one containing rootfs/).",
    )

    args = ap.parse_args(argv if argv is not None else None)

    unpacked_dir = Path(args.unpacked_dir).resolve()
    rootfs_dir = unpacked_dir / "rootfs"

    if not rootfs_dir.is_dir():
        print(
            f"[ERROR] rootfs not found in {rootfs_dir}. "
            "Make sure --unpacked-dir points to the 'unpacked' directory from the bundle.",
            file=sys.stderr,
        )
        sys.exit(1)

    safe_name = derive_safe_name_from_rootfs(rootfs_dir)
    out_dir = Path(OUT_BASE_DIR) / safe_name

    print(f"[INFO] Scanning rootfs: {rootfs_dir}")
    print(f"[INFO] image_safe_name: {safe_name}")
    print(f"[INFO] Output directory: {out_dir}")

    findings = scan_rootfs_for_secrets(
        rootfs_dir=rootfs_dir,
        regex_rules=BUILTIN_REGEX_RULES,
        min_entropy_length=MIN_ENTROPY_LENGTH,
        min_entropy_value=MIN_ENTROPY_VALUE,
    )
    print(f"[INFO] Internal findings (regex+entropy): {len(findings)}")

    print("[INFO] Running TruffleHog...")
    th_findings = run_trufflehog_on_rootfs(
        rootfs_dir=rootfs_dir,
        executable=TRUFFLEHOG_BIN,
    )
    print(f"[INFO] TruffleHog findings: {len(th_findings)}")
    findings.extend(th_findings)

    print("[INFO] Running Gitleaks...")
    gl_findings = run_gitleaks_on_rootfs(
        rootfs_dir=rootfs_dir,
        executable=GITLEAKS_BIN,
    )
    print(f"[INFO] Gitleaks findings: {len(gl_findings)}")
    findings.extend(gl_findings)

    findings = deduplicate_findings(findings)
    print(f"[INFO] Total findings (deduplicated): {len(findings)}")

    write_json(findings, out_dir, safe_name)
    write_markdown(findings, out_dir, safe_name)

    print("[INFO] JSON/MD report generated.")


if __name__ == "__main__":
    main()
