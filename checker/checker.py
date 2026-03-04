"""
Module 3 – Configuration Checker (OCI layout)

Objective
---------
Read a container image in **OCI image-layout** already extracted from Module 1
(`/outputs/fetched_images/extracted_<safe_name>/`) and verify a minimal set
of configuration best practices. The module is **agnostic** regarding the fetch backend
(Docker/Non-Docker; public/private), as it only consumes local files (`index.json`, `blobs/...`).

USAGE
-----
$ python checker.py \
    --oci-dir outputs/fetched_images/extracted_<safe_name> \
    [--rules rules.yml]

The output is always written in:
`outputs/checked/<safe_name>/` (where `<safe_name>` is derived from the folder name `extracted_<safe_name>`).

If `--rules` is not passed, the tool uses a **built-in set of rules**.

Output
------
- JSON:  outputs/checked/<safe_name>/config_issues.json
- MD  :  outputs/checked/<safe_name>/config_issues.md

Dependencies
----------
Only the standard library. If available, `pyyaml` will be used to load rules from YAML.
"""
from __future__ import annotations

import sys
import argparse
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple
import shutil
import subprocess

# ------------------------------------------------------------
# Utility: Dive on the tar produced by Module 1
# ------------------------------------------------------------

def _format_bytes(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


from json import JSONDecoder, JSONDecodeError

def run_dive_on_tar(safe_name: str, out_dir: Path) -> Optional[Dict[str, Any]]:
    """Runs Dive in CI mode on the tar if present. Returns a summary or None.

    Assumes the tar was created by the fetcher in:
      outputs/fetched_images/<safe_name>.tar
    """
    tar_path = Path("outputs/fetched_images") / f"{safe_name}.tar"
    if not tar_path.exists():
        print(f"[INFO] Tar not found: {tar_path} (skipping Dive)")
        return None

    exe = shutil.which("dive")
    if not exe:
        print("[INFO] 'dive' not found in PATH (skipping Dive)")
        return None

    ext_dir = out_dir / "external"
    ext_dir.mkdir(parents=True, exist_ok=True)
    dive_json_path = ext_dir / "dive.json"

    cmd = [
        exe,
        "--ci",
        "--source", "docker-archive",
        "--json", str(dive_json_path),
        str(tar_path),
    ]
    print(f"[INFO] Running Dive: {' '.join(cmd)}")

    # --- Runs Dive capturing stdout/stderr ---
    proc = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
    )

    # --- Removes ANSI color codes from Dive output ---
    ansi_escape = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

    stdout_clean = ansi_escape.sub("", proc.stdout or "")
    stderr_clean = ansi_escape.sub("", proc.stderr or "")

    if stdout_clean:
        
        print(stdout_clean, end="")
    if stderr_clean:
        print(stderr_clean, end="", file=sys.stderr)

    if proc.returncode != 0:
        print(f"[WARN] Dive ended with code {proc.returncode}. The output may be incomplete.")

    # ---------- Robust parsing of Dive JSON ---------------
    try:
        text = dive_json_path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"[WARN] Unable to read dive.json: {e}")
        return None

    dec = JSONDecoder()
    idx = 0
    n = len(text)

    # skips initial whitespace
    while idx < n and text[idx].isspace():
        idx += 1
    if idx >= n:
        print("[WARN] dive.json is empty.")
        return None

    try:
        raw, end = dec.raw_decode(text, idx)
    except JSONDecodeError as e:
        print(f"[WARN]  Unable to decode dive.json: {e}")
        return None

    if not isinstance(raw, dict):
        print("[WARN] First JSON value is not a dictionary (dict).")
        return None

    obj = raw

    # --------- Extracts the data we care about ----------------
    image = obj.get("image") or {}
    score = image.get("efficiencyScore")
    wasted = image.get("inefficientBytes")

    layers = obj.get("layers") or obj.get("layer") or []
    largest_layers: List[Dict[str, Any]] = []
    top_files: List[Dict[str, Any]] = []

    # Largest layers
    if isinstance(layers, list):
        tmp_layers = []
        for l in layers:
            dig = l.get("digestId") or l.get("id")
            sz = l.get("sizeBytes") or l.get("uncompressedSize") or 0
            if dig and isinstance(sz, int):
                tmp_layers.append({"digest": dig, "size": sz})
        largest_layers = sorted(tmp_layers, key=lambda x: x["size"], reverse=True)[:3]

    # Largest files (from image.fileReference)
    file_ref = image.get("fileReference") or []
    if isinstance(file_ref, list):
        tmpf = []
        for fr in file_ref:
            pth = fr.get("file")
            sz = fr.get("sizeBytes") or 0
            if pth and isinstance(sz, int):
                tmpf.append({"path": pth, "size": sz})
        tmpf = sorted(tmpf, key=lambda x: x["size"], reverse=True)[:5]
        top_files = [
            {"path": x["path"], "size": x["size"], "layer": "<unknown>"}
            for x in tmpf
        ]

    return {
        "efficiency_score": score,
        "wasted_bytes": wasted,
        "largest_layers": [
            {
                "digest": x["digest"],
                "size_bytes": x["size"],
                "size_h": _format_bytes(x["size"]),
            }
            for x in largest_layers
        ],
        "top_files": [
            {
                "path": x["path"],
                "size_bytes": x["size"],
                "size_h": _format_bytes(x["size"]),
                "layer": x["layer"],
            }
            for x in top_files
        ],
        "raw_path": str(dive_json_path),
    }



# ------------------------------------------------------------
#  Utility: OCI descriptor/variant classification
# ------------------------------------------------------------

def _read_json(p: Path) -> Any:
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def _classify_descriptor(oci_dir: Path, desc: Dict[str, Any]) -> Dict[str, Any]:
    mt = (desc.get("mediaType") or "").lower()
    digest = desc.get("digest", "")
    out = {
        "mediaType": mt,
        "kind": "unknown",
        "selectable": False,
        "config_os": None,
        "config_arch": None,
    }

    if mt.endswith("image.index.v1+json"):
        out.update(kind="index")
        return out

    # Some artifacts declare it here already
    if desc.get("artifactType") or desc.get("subject"):
        out.update(kind="artifact")
        return out

    try:
        algo, h = digest.split(":", 1)
        obj = _read_json(oci_dir / "blobs" / algo / h)
        mt2 = (obj.get("mediaType") or mt).lower()

        # Artifact “disguised” as an image manifest
        if obj.get("artifactType") or obj.get("subject"):
            out.update(mediaType=mt2, kind="artifact")
            return out

        if mt2.endswith("image.manifest.v1+json"):
            cfg_desc = obj.get("config") or {}
            layers = obj.get("layers") or []

            # 1) Read OS/arch from the config BLOB
            cfg_ok = False
            if "digest" in cfg_desc:
                calgo, chash = cfg_desc["digest"].split(":", 1)
                cfg_obj = _read_json(oci_dir / "blobs" / calgo / chash)
                out["config_os"] = cfg_obj.get("os")
                out["config_arch"] = cfg_obj.get("architecture")

                # The mediaType of the CONFIG should be taken from the manifest descriptor, not from the blob
                cfg_desc_mt = (cfg_desc.get("mediaType") or "").lower()
                # Consider the config valid if it has OS+ARCH and the descriptor mediaType is from image.config
                cfg_ok = bool(out["config_os"] and out["config_arch"]) and (
                    cfg_desc_mt.endswith("image.config.v1+json") or cfg_desc_mt == ""
                )

            # 2) There must be at least one "filesystem" layer
            def is_fs_layer(lmt: str) -> bool:
                lmt = (lmt or "").lower()
                return ("image.layer" in lmt) or ("rootfs" in lmt)  # covers OCI and Docker

            has_fs_layer = any(is_fs_layer(l.get("mediaType")) for l in layers)

            if cfg_ok and has_fs_layer:
                out.update(mediaType=mt2, kind="image", selectable=True)
            else:
                out.update(mediaType=mt2, kind="artifact", selectable=False)
        else:
            out.update(mediaType=mt2, kind="unknown", selectable=False)
    except Exception:
        out.update(kind="missing", selectable=False)

    return out


def _list_variants(oci_dir: Path, manifests: List[Dict[str, Any]]) -> List[int]:
    """Prints only selectable variants (kind=image) and
    returns a list of original indices.

    The return value is a list:
        display_idx -> original_index in manifests
    """
    selectable: List[Tuple[int, Dict[str, Any], Dict[str, Any]]] = []
    for i, m in enumerate(manifests):
        cls = _classify_descriptor(oci_dir, m)
        if not cls["selectable"]:
            continue  # hides artifact / non-images
        selectable.append((i, m, cls))

    if not selectable:
        print("\nNo selectable variants found in the image index.")
        return []

    print("\nAvailable variants in the image index (only real images):")
    print(
        "  Id   OS/Arch        Digest                                                                    Size"
    )
    print(
        "  ---- -------------  -----------------------------------------------------------------------   -----"
    )

    for display_idx, (orig_i, m, cls) in enumerate(selectable):
        p = m.get("platform", {})
        os_ = p.get("os", cls.get("config_os") or "?") or "unknown"
        arch = p.get("architecture", cls.get("config_arch") or "?") or "unknown"
        platform = f"{os_}/{arch}"

        sz = m.get("size")
        size_s = _format_bytes(sz) if isinstance(sz, int) else "?"

        digest = m.get("digest") or ""

        
        print(
            f"  [{display_idx:>2}] {platform:<13}  {digest}  {size_s:>6}"
        )

    
    return [orig_i for (orig_i, _m, _cls) in selectable]



def _select_manifest(
    oci_dir: Path, manifests: List[Dict[str, Any]], want_platform: Optional[str]
) -> Dict[str, Any]:
    
    # TTY input required for both stdin and stdout
    interactive = sys.stdin.isatty() and sys.stdout.isatty()

    # 1) If the user has passed --platform os/arch, try that
    if want_platform:
        try:
            want_os, want_arch = want_platform.split("/", 1)
        except ValueError:
            raise RuntimeError(
                "Invalid --platform format. Use os/arch (e.g., linux/amd64)."
            )
        for m in manifests:
            p = m.get("platform", {})
            cls = _classify_descriptor(oci_dir, m)

            cand_os = p.get("os") or cls.get("config_os")
            cand_arch = p.get("architecture") or cls.get("config_arch")
            if cand_os == want_os and cand_arch == want_arch and cls["selectable"]:
                return m
        # Not found: build available list
        print(f"[WARN] Requested platform not available: {want_platform}")
        if interactive:
            # Fallback: interactive prompt
            return _select_manifest(oci_dir, manifests, None)  # switch to interactive mode
        else:
            print("Choose from the following next time:")
            _list_variants(oci_dir, manifests)
            # Non-interactive environment (CI): raise error after showing the table
            raise RuntimeError(
                "Multi-arch index detected and --platform does not match any variant. "
                "Consult the table above and specify a valid platform (e.g., --platform linux/amd64)."
            )

    # 2) If not interactive (CI), we cannot ask for input: fail with clear instruction
    if not interactive:
        print("[INFO] Multi-arch index detected.")
        print("Choose from the following next time:")
        _list_variants(oci_dir, manifests)  # just to show options
        raise RuntimeError(
            "Multi-arch index detected. Specify --platform (e.g., --platform linux/amd64) in non-interactive environments."
        )

    # 3) Interactive: list and ask (only selectable variants)
    print("Choose from the following available options:")
    selectable_indices = _list_variants(oci_dir, manifests)
    if not selectable_indices:
        raise RuntimeError("No selectable image variants found in the index.")

    while True:
        choice = input("Select the index of the variant to use [0]: ").strip()
        if choice == "":
            idx = 0
        else:
            if not choice.isdigit():
                print("Please enter a valid number.")
                continue
            idx = int(choice)

        if 0 <= idx < len(selectable_indices):
            orig_idx = selectable_indices[idx]
            pick = manifests[orig_idx]
            return pick
        else:
            print(f"Index out of range (0..{len(selectable_indices)-1}). Try again.")


# ------------------------------------------------------------
# Utility: Loading OCI manifest/config from index.json
# ------------------------------------------------------------

def load_oci_objects(
    oci_dir: Path, want_platform: Optional[str] = None
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Returns (manifest, config) as dict.

    Assumptions:
    - oci_dir contains `index.json` and folder `blobs/<algo>/<digest>`
    - uses the first manifest in index.json
    """

    index = _read_json(oci_dir / "index.json")
    if not index.get("manifests"):
        raise RuntimeError("index.json does not contain any manifests")

    # 1) Take the first descriptor from the root index
    desc = index["manifests"][0]
    algo, h = desc["digest"].split(":", 1)
    first_blob = _read_json(oci_dir / "blobs" / algo / h)

    # 2) If the first blob is STILL an image index, choose a platform (e.g., linux/amd64)
    if first_blob.get("mediaType", "").endswith("image.index.v1+json"):
        manifests = first_blob.get("manifests", [])
        if not manifests:
            raise RuntimeError("Empty image index")

        # use --platform if passed, otherwise interactive prompt / error in CI
        pick = _select_manifest(oci_dir, manifests, want_platform)
        algo2, h2 = pick["digest"].split(":", 1)
        manifest = _read_json(oci_dir / "blobs" / algo2 / h2)
    else:
        # otherwise, the first blob is already a manifest
        manifest = first_blob

    # 3) From the manifest, get the config
    cfg_algo, cfg_hash = manifest["config"]["digest"].split(":", 1)
    config = _read_json(oci_dir / "blobs" / cfg_algo / cfg_hash)
    return manifest, config


# ------------------------------------------------------------
# Light reconstruction of the Dockerfile from history
# ------------------------------------------------------------

def reconstruct_pseudo_dockerfile(config: Dict[str, Any]) -> List[str]:
    """Extracts a series of pseudo-instructions from the history (created_by).
    Not perfect, but useful for textual checks and heuristics.
    """
    dockerfile: List[str] = []
    for h in config.get("history", []):
        cmd = h.get("created_by") or ""
        # Normalize
        cmd = re.sub(r"^/bin/sh -c #\(nop\) ", "", cmd)
        cmd = re.sub(r"^/bin/sh -c ", "RUN ", cmd)
        dockerfile.append(cmd.strip())
    return dockerfile


# ------------------------------------------------------------
# Rules (built-in) + optional external loading
# ------------------------------------------------------------

BUILTIN_RULES: List[Dict[str, Any]] = [
    {
        "id": "ROOT_USER",
        "description": "Container gira come utente root o utente non specificato",
        "severity": "High",
        "check": lambda cfg, df: (
            not cfg.get("config", {}).get("User")
        ) or (cfg.get("config", {}).get("User") == "root"),
        "hint": "Imposta un utente non privilegiato (USER) o usa runAsNonRoot a deploy time.",
    },
    {
        "id": "MISSING_HEALTHCHECK",
        "description": "Assenza di HEALTHCHECK",
        "severity": "Medium",
        "check": lambda cfg, df: not cfg.get("config", {}).get("Healthcheck"),
        "hint": "Aggiungi HEALTHCHECK per rilevare stati non sani.",
    },
    {
        "id": "ADD_INSTEAD_OF_COPY",
        "description": "Uso di ADD invece di COPY nella build",
        "severity": "Low",
        "check": lambda cfg, df: any(line.startswith("ADD ") for line in df),
        "hint": "Preferisci COPY ad ADD salvo necessità (URL/extract).",
    },
    {
        "id": "PACKAGE_CACHE_NOT_CLEANED",
        "description": "Installazioni di pacchetti senza cleanup (heuristic)",
        "severity": "Low",
        "check": lambda cfg, df: any(
            (
                ("apt-get install" in line and ("rm -rf /var/lib/apt/lists" not in line))
                or ("apk add" in line and ("--no-cache" not in line and "apk del" not in line))
                or ("yum install" in line and ("clean all" not in line))
            ) and line.startswith("RUN ")
            for line in df
        ),
        "hint": "Pulisci cache (apt/yum) o usa apk --no-cache per ridurre size e superficie d'attacco.",
    },
    {
        "id": "NO_USER_SET",
        "description": "Nessuna istruzione USER nella Dockerfile ricostruita",
        "severity": "Low",
        "check": lambda cfg, df: not any(line.startswith("USER ") for line in df),
        "hint": "Aggiungi USER non privilegiato nella Dockerfile.",
    },
    {
        "id": "EXPOSE_PORT_80",
        "description": "Porta 80 esposta (HTTP non cifrato)",
        "severity": "Low",
        "check": lambda cfg, df: any(
            p == 80
            for p in cfg.get("config", {}).get("ExposedPorts", {}).keys()
            if isinstance(p, int) or (isinstance(p, str) and p.startswith("80"))
        )
        if isinstance(cfg.get("config", {}).get("ExposedPorts"), dict)
        else False,
        "hint": "Considera l'uso di HTTPS (porta 443) o un reverse proxy.",
    },
    {
        "id": "MISSING_CMD",
        "description": "Nessun CMD definito",
        "severity": "Info",
        "check": lambda cfg, df: not cfg.get("config", {}).get("Cmd"),
        "hint": "Definisci un CMD esplicito per chiarezza.",
    },
    {
        "id": "EXPOSE_SSH",
        "description": "EXPOSE include la porta 22 (SSH)",
        "severity": "High",
        "check": lambda cfg, df: any(
            p in {"22/tcp", "22/udp"}
            for p in (cfg.get("config", {}).get("ExposedPorts") or {}).keys()
        ),
        "hint": "Evita di esporre SSH dal container; rimuovi EXPOSE 22 o usa canali amministrativi alternativi.",
    },
    {
        "id": "EXPOSE_PRIVILEGED_PORTS",
        "description": "EXPOSE su porte privilegiate (<1024) non standard",
        "severity": "Medium",
        "check": lambda cfg, df: any(
            (lambda n, proto:
                (n is not None)
                and (n < 1024)
                and (f"{n}/{proto}" not in {"80/tcp", "443/tcp", "53/tcp", "53/udp"})
            )(
                (int(k.split("/",1)[0]) if ("/" in k and k.split("/",1)[0].isdigit()) else None),
                (k.split("/",1)[1] if "/" in k else "tcp")
            )
            for k in (cfg.get("config", {}).get("ExposedPorts") or {}).keys()
        ),
        "hint": "Usa porte >1024 nel container (es. 8080) e mappa a 80/443 a runtime.",
    },
    {
        "id": "EXPOSE_NOTE",
        "description": "Nota: EXPOSE è solo documentativo; il binding reale dipende dal runtime",
        "severity": "Info",
        "check": lambda cfg, df: bool((cfg.get("config", {}).get("ExposedPorts") or {})),
        "hint": "Proteggi con policy di rete/ingress e binding espliciti in deploy (Kubernetes/compose).",
    },
    {
        "id": "VOLUME_ROOTLIKE",
        "description": "VOLUME su path ampio o sensibile (/ /root /etc /var)",
        "severity": "Medium",
        "check": lambda cfg, df: any(
            v in {"/", "/root", "/etc", "/var"}
            for v in (cfg.get("config", {}).get("Volumes") or {}).keys()
        ),
        "hint": "Usa path specifici e minimi per la persistenza (es. /var/app/data).",
    },
    {
        "id": "VOLUME_ABSENCE_NOTE",
        "description": "Nota: nessun VOLUME dichiarato (se serve persistenza, dichiararlo aiuta)",
        "severity": "Info",
        "check": lambda cfg, df: not (cfg.get("config", {}).get("Volumes") or {}),
        "hint": "Se l’app scrive dati che devono persistere, dichiara un VOLUME dedicato.",
    },
]


def load_rules(path: Path) -> List[Dict[str, Any]]:
    """Load rules from YAML or JSON.
    Expected format (YAML/JSON):
      rules:
        - id: "ROOT_USER"
          description: "Container runs as root"
          severity: "High"
          pattern: "USER root"          # regex on Dockerfile lines
          config_key: "config.User"     # key in the JSON config
          equals: "root"                # expected value (optional)
    """
    if not path.is_file():
        raise FileNotFoundError(f"Rules file not found: {path}")

    try:
        import yaml  # type: ignore

        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        rules = data.get("rules", data)
        if not isinstance(rules, list):
            raise ValueError("Invalid rules format")

        compiled: List[Dict[str, Any]] = []
        for r in rules:
            rid = r.get("id")
            desc = r.get("description", "")
            sev = r.get("severity", "Low")
            pattern = r.get("pattern")  
            config_key = r.get("config_key") 
            equals = r.get("equals")

            def make_check(
                pattern: Optional[str], config_key: Optional[str], equals: Any
            ):
                def _check(cfg, df):
                    ok = False
                    if pattern:
                        rx = re.compile(pattern)
                        ok = any(rx.search(line or "") for line in df)
                    if config_key is not None:
                        parts = config_key.split(".")
                        cur: Any = cfg
                        for p in parts:
                            cur = cur.get(p) if isinstance(cur, dict) else None
                        if equals is not None:
                            ok = ok or (cur == equals)
                        else:
                            ok = ok or (cur in (None, "", []))
                    return ok

                return _check

            check_fn = make_check(pattern, config_key, equals)
            compiled.append(
                {
                    "id": rid,
                    "description": desc,
                    "severity": sev,
                    "check": check_fn,
                    "hint": r.get("hint", ""),
                }
            )
        return compiled
    except Exception:
        # Try JSON: rules list with keys compatible with the above
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        rules = data.get("rules", data)
        compiled: List[Dict[str, Any]] = []
        for r in rules:
            rid = r.get("id")
            desc = r.get("description", "")
            sev = r.get("severity", "Low")
            pattern = r.get("pattern")
            config_key = r.get("config_key")
            equals = r.get("equals")
            hint = r.get("hint", "")

            def make_check(
                pattern: Optional[str], config_key: Optional[str], equals: Any
            ):
                def _check(cfg, df):
                    ok = False
                    if pattern:
                        rx = re.compile(pattern)
                        ok = any(rx.search(line or "") for line in df)
                    if config_key is not None:
                        parts = config_key.split(".")
                        cur: Any = cfg
                        for p in parts:
                            cur = cur.get(p) if isinstance(cur, dict) else None
                        if equals is not None:
                            ok = ok or (cur == equals)
                        else:
                            ok = ok or (cur in (None, "", []))
                    return ok

                return _check

            check_fn = make_check(pattern, config_key, equals)
            compiled.append(
                {
                    "id": rid,
                    "description": desc,
                    "severity": sev,
                    "check": check_fn,
                    "hint": hint,
                }
            )
        return compiled


# ------------------------------------------------------------
# Running the checks and reporting
# ------------------------------------------------------------

SEVERITY_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Info": 0}


def run_checks(
    config: Dict[str, Any], dockerfile_lines: List[str], rules: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for r in rules:
        try:
            triggered = r["check"](config, dockerfile_lines)
        except Exception:
            triggered = False
        if triggered:
            findings.append(
                {
                    "id": r.get("id"),
                    "description": r.get("description"),
                    "severity": r.get("severity", "Low"),
                    "hint": r.get("hint", ""),
                }
            )
    findings.sort(key=lambda x: (-SEVERITY_ORDER.get(x["severity"], 0), x["id"]))
    return findings


def to_markdown(
    safe_name: str,
    findings: List[Dict[str, Any]], 
    meta: Dict[str, Any],
    dive: Optional[Dict[str, Any]] = None,
) -> str:
    lines: List[str] = []
    lines.append(f"# Configuration Issues — {safe_name}")
    img = meta.get("image")
    if img:
        lines.append(f"*Image:* `{img}`\n")
    base = meta.get("base")
    if base:
        lines.append(f"*Base image:* `{base}`\n")

    if dive:
        lines.append("\n## Efficienza (Dive)")
        score = dive.get("efficiency_score")
        wasted = dive.get("wasted_bytes")
        if score is not None:
            lines.append(f"- **Efficiency score:** {score}")
        if wasted is not None:
            lines.append(f"- **Wasted bytes:** ~{_format_bytes(wasted)}")
        if dive.get("largest_layers"):
            lines.append("- **Layer più grandi:**")
            for ll in dive["largest_layers"]:
                lines.append(f"  - `{ll['digest']}` — {ll['size_h']}")
        if dive.get("top_files"):
            lines.append("- **File più pesanti (top 5):**")
            for tf in dive["top_files"]:
                lines.append(
                    f"  - `{tf['path']}` — {tf['size_h']} (layer {tf['layer']})"
                )

    lines.append("\n## Findings\n")
    if not findings:
        lines.append("Nessun problema rilevato. \n")
        return "\n".join(lines)
    for f in findings:
        lines.append(f"- **[{f['severity']}] {f['id']}** — {f['description']}")
        if f.get("hint"):
            lines.append(f"  \n  Suggerimento: _{f['hint']}_")
    return "\n".join(lines)


def _is_valid_oci_dir(p: Path) -> bool:
    return (
        p.is_dir()
        and (p / "index.json").is_file()
        and (p / "oci-layout").is_file()
        and (p / "blobs").is_dir()
    )


def _derive_safe_name(oci_dir: Path) -> str:
    # oci_dir.name is like "extracted_<safe_name>"
    name = oci_dir.name
    return name.replace("extracted_", "", 1) or name


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Module 3 – Configuration Checker (OCI layout)"
    )
    ap.add_argument(
        "--oci-dir",
        required=True,
        help="Path to extracted_<safe_name> (OCI image-layout)",
    )
    ap.add_argument(
        "--rules",
        help="Rules file (YAML or JSON). If omitted, uses built-in rules",
    )
    ap.add_argument(
        "--platform",
        help=(
            "Select the manifest platform (e.g., linux/amd64). "
            "If omitted and the image is multi-arch: interactive prompt in TTY, "
            "explicit error in non-interactive environments (CI)."
        ),
    )
    args = ap.parse_args()
    want_platform = args.platform

    try:
        oci_dir = Path(args.oci_dir).resolve()
        print(f"[INFO] OCI dir: {oci_dir}")
        if not _is_valid_oci_dir(oci_dir):
            raise RuntimeError(
                f"Invalid OCI dir: {oci_dir} (missing index.json / oci-layout / blobs/)"
            )

        safe_name = _derive_safe_name(oci_dir)
        print(f"[INFO] safe_name: {safe_name}")

        out_root = Path("outputs/checked").resolve()
        out_dir = out_root / safe_name
        print(f"[INFO] output dir: {out_dir}")
        out_dir.mkdir(parents=True, exist_ok=True)

        # Load manifest and config for the selected platform
        manifest, config = load_oci_objects(oci_dir, want_platform)
        dockerfile_lines = reconstruct_pseudo_dockerfile(config)

        # Load rules (external or built-in)
        rules = load_rules(Path(args.rules)) if args.rules else BUILTIN_RULES

        # Run the checks
        findings = run_checks(config, dockerfile_lines, rules)

        # Context metadata for the report
        base_image = None
        for line in dockerfile_lines:
            if line.startswith("FROM "):
                base_image = line.split(" ", 1)[1].strip()
                break
        meta = {"image": safe_name, "base": base_image}

        # Dive: always best-effort on the tar generated by Module 1
        dive_summary = run_dive_on_tar(safe_name, out_dir)

        # Save JSON
        json_path = out_dir / "config_issues.json"
        payload = {
            "image": safe_name,
            "findings": findings,
            "counts": {
                "total": len(findings),
                "by_severity": {
                    s: sum(1 for x in findings if x["severity"] == s)
                    for s in ("High", "Medium", "Low", "Info")
                },
            },
        }
        if dive_summary:
            payload["dive_summary"] = dive_summary

        with json_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

        # Save Markdown
        md_path = out_dir / "config_issues.md"
        md = to_markdown(safe_name, findings, meta, dive_summary)
        md_path.write_text(md, encoding="utf-8")

        print(f"[OK] Analysis completed. JSON: {json_path}")
        print(f"[OK] Markdown: {md_path}")

    except RuntimeError as e:
        
        print(f"[ERROR] {e}")
        sys.exit(1)
    except Exception as e:
        # Any other unexpected error
        print(f"[ERROR] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
