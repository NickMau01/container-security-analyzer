from __future__ import annotations

"""
Fetcher – produces an OCI image layout (for Module 3), a docker-archive tar (for Module 2/Dive),
and performs an 'umoci unpack' to materialize the rootfs (for Module 4).

Usage examples:

  # Multi-arch index (all platforms), select a platform interactively if run in a TTY
  python newfetch3.py --image nginx:latest

  # Single platform only (no multi-arch index), unpack that exact variant
  python newfetch3.py --image nginx:latest --platform linux/amd64

Notes:
  - OCI image-layout directory:
        outputs/fetched_images/extracted_<safe_name>
  - docker-archive tar (single-platform, coherent with unpack):
        outputs/fetched_images/<safe_name>.tar
  - Unpacked bundle:
        outputs/fetched_images/extracted_<safe_name>/unpacked/
    with:
        ./unpacked/rootfs/      (final filesystem)
        ./unpacked/config.json  (OCI runtime bundle config)
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import shlex
from pathlib import Path
from typing import Dict, Optional, List, Tuple
import sys
import stat

# ---------------------------------------------------------------------------
# Constant: fixed output directory
# ---------------------------------------------------------------------------

OUT_ROOT = Path("outputs/fetched_images").resolve()


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command, logging it beforehand."""
    print("[CMD]", " ".join(cmd))
    if os.name == "nt":
        # Run inside WSL (PATH and tools are those of Ubuntu)
        quoted = " ".join(shlex.quote(c) for c in cmd)
        return subprocess.run(["wsl", "bash", "-lc", quoted], check=check)
    return subprocess.run(cmd, check=check)


def _to_wsl_posix(p) -> str:
    """
    Convert a path into a POSIX-like path suitable for skopeo/umoci under Windows/WSL.

    Examples:
      C:\\Users\\nick\\file.tar  ->  /mnt/c/Users/nick/file.tar
      /mnt/c/Users/nick/file.tar ->  /mnt/c/Users/nick/file.tar (unchanged)
    """
    s = str(p)
    # Already a /mnt/... path
    if s.startswith("/mnt/"):
        return s

    if os.name == "nt":
        drive, rest = os.path.splitdrive(s)      # es. C:  \Users\...
        rest = rest.replace("\\", "/")
        # Avoid double /mnt if someone already passed a /mnt path under C:\mnt\...
        if rest.startswith("/mnt/"):
            return rest
        if drive:
            letter = drive.rstrip(":").lower()   # C: -> c
            return f"/mnt/{letter}{rest}"
        return rest

    # Non-Windows: just normalize backslashes if any
    return s.replace("\\", "/")


def _which(name: str) -> Optional[str]:
    """which on Windows; if not found, try 'command -v' in WSL."""
    p = shutil.which(name)
    if p:
        return p
    if os.name == "nt" and shutil.which("wsl"):
        try:
            res = subprocess.run(
                ["wsl", "bash", "-lc", f"command -v {shlex.quote(name)}"],
                capture_output=True, text=True
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass
    return None


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def _rmtree_force(path: Path) -> None:
    """
    Like shutil.rmtree, but if it encounters a PermissionError, try removing
    the read-only option and retrying. If that fails, it throws the error again.
    """
    if not path.exists():
        return

    def _onerror(func, p, exc_info):
        exc = exc_info[1]
        # If the path no longer exists in the meantime, exit
        if not os.path.exists(p):
            return
        if isinstance(exc, PermissionError):
            try:
                # try to make it writable
                os.chmod(p, stat.S_IWRITE)
            except OSError:
                pass
            # try again
            func(p)
        else:
            # other errors
            raise exc

    shutil.rmtree(path, onerror=_onerror)



def _safe_name(image: str) -> str:
    """
    Make the image name safe to use in the filesystem.

    Example:
      "docker.io/library/nginx:latest" -> "docker.io_library_nginx_latest"
    """
    s = image.strip()
    s = s.replace("/", "_").replace(":", "_").replace("@", "_")
    s = re.sub(r"[^A-Za-z0-9._-]", "_", s)
    return s


def _read_index_json(oci_dir: Path) -> Optional[dict]:
    """Load index.json from an OCI layout if present."""
    idx = oci_dir / "index.json"
    if not idx.is_file():
        return None
    with idx.open("r", encoding="utf-8") as f:
        return json.load(f)


def _read_json(p: Path):
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def _format_bytes(n: int) -> str:
    """Format byte size in a human-readable way (es. '2.2KB')."""
    n = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if n < 1024.0:
            # a decimal place, truncating zeros for B
            if unit == "B":
                return f"{int(n)}{unit}"
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"


# ---------------------------------------------------------------------------
# Multi-arch variants helpers
# ---------------------------------------------------------------------------

def _read_multiarch_variants(oci_dir: Path, safe_name: str) -> List[dict]:
    """
    Returns a list of descriptors (manifests) for the ref 'safe_name',
    filtering out artifacts/unknowns (only true platform images).
    """
    index = _read_json(oci_dir / "index.json")

    # 1) Find the descriptor that points to the safe_name ref (e.g., "nginx_latest")
    ref_desc = None
    for desc in index.get("manifests", []):
        ann = desc.get("annotations") or {}
        if ann.get("org.opencontainers.image.ref.name") == safe_name:
            ref_desc = desc
            break

    if not ref_desc:
        raise RuntimeError(f"Could not find ref '{safe_name}' in index.json")

    # 2) open the blob (manifest-list)
    algo, h = ref_desc["digest"].split(":", 1)
    ml = _read_json(oci_dir / "blobs" / algo / h)
    manifests = ml.get("manifests") or []

    # 3) Filter only those with a “real” platform (no unknown/unknown)
    real_variants: List[dict] = []
    for m in manifests:
        plat = m.get("platform") or {}
        os_ = (plat.get("os") or "").lower()
        arch = (plat.get("architecture") or "").lower()
        if os_ and arch and os_ != "unknown" and arch != "unknown":
            real_variants.append(m)

    if not real_variants:
        raise RuntimeError("No selectable variants found in the image index")

    return real_variants


def _read_available_platforms(oci_dir: Path, safe_name: str) -> List[Tuple[str, str]]:
    """
    Returns the list of (os, arch) available for the ref 'safe_name',
    using the same filtering logic as _read_multiarch_variants.
    """
    try:
        variants = _read_multiarch_variants(oci_dir, safe_name)
    except Exception:
        return []

    plats: List[Tuple[str, str]] = []
    for m in variants:
        plat = m.get("platform") or {}
        os_ = plat.get("os")
        arch = plat.get("architecture")
        if os_ and arch:
            plats.append((os_, arch))
    return plats


def _choose_platform_interactive(oci_dir: Path, safe_name: str) -> Tuple[str, str]:
    """
    Displays the variant table and returns (os, arch)
    selected by the user.
    """
    variants = _read_multiarch_variants(oci_dir, safe_name)

    print("Variants available in the image index (real images only):")
    print(
        "  Id   OS/Arch        Digest                                                                    Size"
    )
    print(
        "  ---- -------------  -----------------------------------------------------------------------   -----"
    )

    plats: List[Tuple[str, str]] = []

    for idx, m in enumerate(variants):
        plat = m.get("platform") or {}
        os_ = plat.get("os") or "unknown"
        arch = plat.get("architecture") or "unknown"
        digest = m.get("digest", "")
        size = m.get("size") or 0

        platform = f"{os_}/{arch}"
        plats.append((os_, arch))

        print(
            f"  [{idx:2d}] {platform:<13}  {digest:<67} {_format_bytes(size):>6}"
        )

    # default = 0 (which is usually linux/amd64 if present)
    default_idx = 0
    raw = input(f"Select the variant index to use [{default_idx}]: ").strip()
    if not raw:
        choice = default_idx
    else:
        try:
            choice = int(raw)
        except ValueError:
            raise SystemExit("Invalid index.")

    if choice < 0 or choice >= len(plats):
        raise SystemExit("Index out of range.")

    sel_os, sel_arch = plats[choice]
    print(f"[INFO] Selected {sel_os}/{sel_arch} for tar + unpack.")
    return sel_os, sel_arch


def _print_platform_choices(plats: List[Tuple[str, str]]) -> None:
    print("Available platforms:")
    for i, (os_, arch) in enumerate(plats):
        print(f"  [{i}] {os_}/{arch}")


# ---------------------------------------------------------------------------
# Single backend: skopeo + always-unpack via umoci
# ---------------------------------------------------------------------------

def fetch_with_skopeo(
    image: str,
    out_root: Path,
    platform: Optional[str],
) -> Dict:
    """
    Use skopeo to:
      - create an OCI image-layout in: out_root / f"extracted_<safe_name>"
      - always create a docker-archive tar in: out_root / f"<safe_name>.tar"
    And then always performs 'umoci unpack' to produce a runtime bundle with rootfs.

    Behavior:
      - OCI dir, tar, and unpack dir are always removed if they already exist.
      - If --platform is provided:
          * In the presence of platform metadata:
              - if it exists, use it.
              - if it does NOT exist:
                  - if TTY: show variants table and ask which one to use instead.
                  - if not TTY: print list and raise an error.
          * If there is no platform metadata: trusts and uses the requested platform.
      - If --platform is NOT provided:
          * If platform metadata exists:
              - if TTY: show variants table and ask which one to use.
              - if not TTY:
                    - if linux/amd64 exists, use it.
                    - otherwise, print list and raise an error.
          * If no platform metadata:
              - fall back to linux/amd64 by convention and try anyway.
    """
    if not _which("skopeo"):
        raise RuntimeError("skopeo not found in PATH. Please install skopeo to use newfetch3.")
    if not _which("umoci"):
        raise RuntimeError("umoci not found in PATH. Please install umoci to enable unpack.")

    safe = _safe_name(image)
    oci_dir = out_root / f"extracted_{safe}"
    tar_path = out_root / f"{safe}.tar"
    bundle_dir = oci_dir / "unpacked"  # OCI runtime bundle (rootfs/ + config.json)

    # ------------------------------------------------------------------
    # 0) Clean previous outputs
    # ------------------------------------------------------------------
    if oci_dir.exists():
        print(f"[INFO] Removing existing OCI directory: {oci_dir} (full regeneration).")
        #shutil.rmtree(oci_dir, ignore_errors=True)
        _rmtree_force(oci_dir)
    if tar_path.exists():
        print(f"[INFO] Removing existing tar: {tar_path} (full regeneration).")
        tar_path.unlink(missing_ok=True)
    if bundle_dir.exists():
        print(f"[INFO] Removing existing unpack bundle: {bundle_dir} (full regeneration).")
        #shutil.rmtree(bundle_dir)
        _rmtree_force(bundle_dir)

    _ensure_dir(out_root)

    # ------------------------------------------------------------------
    # 1) OCI image-layout (multi-arch or single-arch depending on --platform)
    # ------------------------------------------------------------------
    src = f"docker://{image}"
    dest = f"oci:{_to_wsl_posix(oci_dir)}:{safe}"

    cmd = ["skopeo", "copy"]
    if platform:
        # platform must be OS/ARCH, es. linux/amd64
        if "/" not in platform:
            raise ValueError("The --platform option must be of the form OS/ARCH, e.g. linux/amd64")
        want_os, want_arch = platform.split("/", 1)
        print(f"[INFO] Using specific platform for OCI layout: os={want_os}, arch={want_arch}")
        cmd += ["--override-os", want_os, "--override-arch", want_arch, src, dest]
    else:
        # full multi-arch index
        print("[INFO] No --platform given: fetching full multi-arch index (--all).")
        cmd += ["--all", src, dest]
    _run(cmd)

    # ------------------------------------------------------------------
    # 2) Determine the “actual” platform to use for tar + unpack
    # ------------------------------------------------------------------
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    plats = _read_available_platforms(oci_dir, safe)  # e.g. [('linux','amd64'), ('linux','arm64'), ...]
    selected_platform: Optional[str] = None

    # -------------------------
    # Case 1: --platform provided
    # -------------------------
    if platform:
        if "/" not in platform:
            raise ValueError("The --platform option must be of the form OS/ARCH, e.g. linux/amd64")
        want_os, want_arch = platform.split("/", 1)

        if plats:
            if (want_os, want_arch) in plats:
                # The requested platform really exists in the manifest-list
                selected_platform = platform
            else:
                if interactive:
                    print(f"[WARN] The requested platform {platform} is not available in the manifest-list.")
                    # Standalone: use table to select an alternative
                    sel_os, sel_arch = _choose_platform_interactive(oci_dir, safe)
                    selected_platform = f"{sel_os}/{sel_arch}"
                else:
                    # Pipeline / non-interactive: show platforms and stop
                    print(f"[WARN] The requested platform {platform} is not available in the manifest-list.")
                    _print_platform_choices(plats)
                    raise RuntimeError(
                        f"Requested platform {platform} not available. "
                        "See the list above and try again specifying a valid platform."
                    )
        else:
            # No platform metadata: we trust the requested platform.
            selected_platform = platform

    # ----------------------------------------
    # Case 2: no --platform provided
    # ----------------------------------------
    else:
        if not plats:
            # No metadata: fallback behavior
            print("[WARN] Manifest-list without platform metadata. "
                  "Falling back to linux/amd64 by convention (tar + unpack).")
            selected_platform = "linux/amd64"
        else:
            if interactive:
                # Standalone: show table and let choose
                print("[INFO] Multi-arch index detected. Select the platform to use for tar + unpack.")
                sel_os, sel_arch = _choose_platform_interactive(oci_dir, safe)
                selected_platform = f"{sel_os}/{sel_arch}"
            else:
                # Pipeline / non-interactive
                if ("linux", "amd64") in plats:
                    selected_platform = "linux/amd64"
                    print("[INFO] Multi-arch detected (no --platform). "
                          "In non-interactive environment using linux/amd64 for tar + unpack.")
                else:
                    print("[WARN] Multi-arch index swithout linux/amd64 and no --platform specified.")
                    _print_platform_choices(plats)
                    raise RuntimeError(
                        "Non-interactive environment: no --platform specified and linux/amd64 is not available. "
                        "Relaunch specifying --platform."
                    )

    # ------------------------------------------------------------------
    # 3) docker-archive tar – single-platform, consistent with selected_platform
    # ------------------------------------------------------------------
    print(f"[INFO] Creating docker-archive tar: {tar_path} (platform={selected_platform})")
    tar_src = f"docker://{image}"

    tar_cmd = ["skopeo", "copy"]

    # elected_platform should always be os/arch at this point
    if not selected_platform or "/" not in selected_platform:
        raise ValueError(f"Internal error: selected_platform must be os/arch, got: {selected_platform!r}")
    t_os, t_arch = selected_platform.split("/", 1)
    tar_cmd += [
        "--override-os", t_os,
        "--override-arch", t_arch,
        tar_src,
        f"docker-archive:{_to_wsl_posix(tar_path)}:{image}",  # for .tar manifest
    ]
    _run(tar_cmd)

    # ------------------------------------------------------------------
    # 4) umoci unpack – uses the same selected_platform
    # ------------------------------------------------------------------
    oci_ref_for_unzip: Optional[str] = None

    if platform:
        # We've already fetched single-arch in the OCI with ref '<safe>'
        oci_ref_for_unzip = f"{_to_wsl_posix(oci_dir)}:{safe}"
    else:
        # We've fetched a multi-arch index: umoci wants a single-arch image.
        # Let's create a new internal ref '<safe>-unpack' filtered on selected_platform.
        u_os, u_arch = selected_platform.split("/", 1)

        dest_ref_name = f"{safe}-unpack"
        print(f"[INFO] Preparing single-arch ref for umoci: {u_os}/{u_arch} -> {dest_ref_name}")
        cmd = [
            "skopeo", "copy",
            "--override-os", u_os, "--override-arch", u_arch,
            f"oci:{_to_wsl_posix(oci_dir)}:{safe}",
            f"oci:{_to_wsl_posix(oci_dir)}:{dest_ref_name}",
        ]
        _run(cmd)
        oci_ref_for_unzip = f"{_to_wsl_posix(oci_dir)}:{dest_ref_name}"

    # Ensure bundle dir is clean and exists
    if bundle_dir.exists():
        #shutil.rmtree(bundle_dir, ignore_errors=True)
        _rmtree_force(bundle_dir)
    _ensure_dir(bundle_dir.parent)

    print(f"[INFO] Unpacking with umoci (platform: {selected_platform or 'unknown'}).")
    _run([
        "umoci", "unpack",
        "--image", oci_ref_for_unzip,
        _to_wsl_posix(bundle_dir),
    ])

    return {
        "image": image,
        "safe_name": safe,
        "oci_dir": str(oci_dir),
        "tar_path": str(tar_path),                  
        "unpacked_dir": str(bundle_dir),           
        "unpacked_platform": selected_platform,     
        "backend": "skopeo",                       
        "platform": platform or "multi-arch",
    }


# ---------------------------------------------------------------------------
# CLI 
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Fetcher – produces OCI image-layout, docker-archive tar, and unpacks rootfs (umoci)."
    )

    ap.add_argument(
        "--image",
        required=True,
        help="Image name, e.g. nginx:latest",
    )
    ap.add_argument(
        "--platform",
        help="Platform, e.g. linux/amd64. If omitted: fetch multi-arch index and select a platform for tar+unpack.",
    )

    args = ap.parse_args()

    # Fixed output directory
    out_root = OUT_ROOT
    _ensure_dir(out_root)

    print(f"[INFO] image: {args.image}")
    print(f"[INFO] requested platform: {args.platform or 'multi-arch (auto-select)'}")
    print(f"[INFO] out: {out_root}")

    result = fetch_with_skopeo(
        image=args.image,
        out_root=out_root,
        platform=args.platform,
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
