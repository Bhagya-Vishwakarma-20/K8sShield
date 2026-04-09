#!/usr/bin/env python3
"""
fetcher.py — Periodic Cluster Graph Fetcher for KubeAttackViz
══════════════════════════════════════════════════════════════════

Runs the full collection → extraction pipeline on a fixed interval
(cron-style) to keep cluster-graph.json up-to-date with live cluster state:

  1. collect_all_resources.py  →  k8s_resources/cluster.json
  2. extract_relationships.py  →  cluster-graph.json

This pairs with watcher.py:
  • fetcher.py  — re-collects & re-extracts the graph every N seconds
  • watcher.py  — detects when the graph file changes and diffs snapshots

Usage:
  python fetcher.py                              # Default: every 60s
  python fetcher.py --interval 30                # Re-fetch every 30s
  python fetcher.py --skip-collect               # Only re-extract (skip kubectl)
  python fetcher.py --once                       # Run once and exit

Stop with Ctrl+C.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ─── Path bootstrap ──────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent
_EXTRACTOR_DIR = _ROOT / "extractor"

# ─── Windows UTF-8 fix ───────────────────────────────────────────────────────
import io as _io
if hasattr(sys.stdout, "buffer"):
    sys.stdout = _io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "buffer"):
    sys.stderr = _io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ─── Defaults ────────────────────────────────────────────────────────────────
COLLECT_SCRIPT     = _EXTRACTOR_DIR / "collect_all_resources.py"
EXTRACT_SCRIPT     = _EXTRACTOR_DIR / "extract_relationships.py"
DEFAULT_RESOURCES  = _EXTRACTOR_DIR / "k8s_resources"
DEFAULT_INPUT      = DEFAULT_RESOURCES / "cluster.json"
DEFAULT_OUTPUT     = _ROOT / "cluster-graph.json"
DEFAULT_INTERVAL   = 60   # seconds between fetches
DEFAULT_CACHE_DIR  = str(_EXTRACTOR_DIR / ".nvd_cache")

# ─── ANSI helpers ─────────────────────────────────────────────────────────────
class C:
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


class GraphFetcher:
    """
    Periodically runs collect_all_resources.py → extract_relationships.py
    to keep cluster-graph.json in sync with the live Kubernetes cluster.

    Flow per cycle:
      1. Run collect_all_resources.py → k8s_resources/cluster.json
      2. Run extract_relationships.py --input ... --output cluster-graph.json
      3. Compare output hash to detect actual changes.
      4. Print a compact summary line.
      5. Sleep for `interval` seconds and repeat.
    """

    def __init__(
        self,
        resources_dir: Path,
        input_file: Path,
        output_file: Path,
        interval: int,
        nvd_api_key: str | None,
        cache_dir: str,
        skip_collect: bool = False,
        run_once: bool = False,
    ):
        self.resources_dir  = resources_dir
        self.input_file     = input_file
        self.output_file    = output_file
        self.interval       = interval
        self.nvd_api_key    = nvd_api_key
        self.cache_dir      = cache_dir
        self.skip_collect   = skip_collect
        self.run_once       = run_once

        self._run_count     = 0
        self._last_hash: str | None = None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _file_hash(self, path: Path) -> str | None:
        """SHA-256 hex digest of a file, or None if unreadable."""
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except (FileNotFoundError, OSError):
            return None

    def _graph_summary(self) -> str:
        """Read the graph file and return a short node/edge count string."""
        try:
            with open(self.output_file, "r") as f:
                data = json.load(f)
            meta = data.get("metadata", {})
            nodes = meta.get("node_count", len(data.get("nodes", [])))
            edges = meta.get("edge_count", len(data.get("edges", [])))
            return f"{nodes} nodes, {edges} edges"
        except Exception:
            return "?"

    def _print_banner(self) -> None:
        print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════════╗
║          🔄  KubeAttackViz — Periodic Graph Fetcher             ║
╚══════════════════════════════════════════════════════════════════╝{C.RESET}
  Collect script : {COLLECT_SCRIPT}
  Extract script : {EXTRACT_SCRIPT}
  Resources dir  : {self.resources_dir}
  Input (cluster): {self.input_file}
  Output (graph) : {self.output_file}
  Interval       : {self.interval}s
  Skip collect   : {self.skip_collect}
  Mode           : {"one-shot" if self.run_once else "continuous"}
""")

    def _run_subprocess_quiet(self, cmd: list[str], label: str, timeout: int = 300) -> tuple[bool, str]:
        """
        Run a subprocess with captured output. Returns (success, stderr_snippet).
        Output is suppressed to keep the console clean during repeated cycles.
        """
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        try:
            result = subprocess.run(
                cmd, cwd=str(_EXTRACTOR_DIR), timeout=timeout,
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                env=env,
            )
            if result.returncode == 0:
                return True, ""
            else:
                # Grab last meaningful line from stderr or stdout for context
                err_lines = (result.stderr or result.stdout or "").strip().splitlines()
                snippet = err_lines[-1] if err_lines else f"exit code {result.returncode}"
                return False, snippet
        except subprocess.TimeoutExpired:
            return False, f"timed out ({timeout}s)"
        except FileNotFoundError:
            return False, "script not found"
        except Exception as exc:
            return False, str(exc)

    def _run_subprocess_verbose(self, cmd: list[str], label: str, timeout: int = 300) -> bool:
        """Run a subprocess with streaming output (used for first run / --once)."""
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        print(f"  {C.DIM}$ {' '.join(cmd)}{C.RESET}")
        try:
            result = subprocess.run(cmd, cwd=str(_EXTRACTOR_DIR), timeout=timeout, env=env)
            if result.returncode == 0:
                print(f"  {C.GREEN}✓ {label} succeeded{C.RESET}")
                return True
            else:
                print(f"  {C.RED}✗ {label} failed (exit code {result.returncode}){C.RESET}")
                return False
        except subprocess.TimeoutExpired:
            print(f"  {C.RED}✗ {label} timed out ({timeout}s limit){C.RESET}")
            return False
        except FileNotFoundError:
            print(f"  {C.RED}✗ Python interpreter or script not found{C.RESET}")
            return False
        except Exception as exc:
            print(f"  {C.RED}✗ {label} error: {exc}{C.RESET}")
            return False

    # ── Core cycle ────────────────────────────────────────────────────────────

    def _run_cycle_verbose(self) -> bool:
        """First run — show full verbose output so user can see pipeline details."""
        self._run_count += 1
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        print(f"\n{C.CYAN}{C.BOLD}{'─' * 66}{C.RESET}")
        print(f"{C.CYAN}{C.BOLD}  🔄 Fetch #{self._run_count} at {ts}{C.RESET}")
        print(f"{C.CYAN}{C.BOLD}{'─' * 66}{C.RESET}\n")

        # Step 1: Collect
        if not self.skip_collect:
            print(f"{C.BOLD}  Step 1/2 ▸ Collecting K8s resources from cluster{C.RESET}")
            collect_cmd = [
                sys.executable, str(COLLECT_SCRIPT),
                "--output", str(self.resources_dir),
            ]
            if not self._run_subprocess_verbose(collect_cmd, "collect_all_resources"):
                print(f"\n{C.RED}  ✗  Collection failed — skipping extraction.{C.RESET}")
                return False
            print()
        else:
            print(f"{C.YELLOW}  Step 1/2 ▸ Collect SKIPPED (--skip-collect){C.RESET}\n")

        # Step 2: Extract
        step_label = "Step 2/2" if not self.skip_collect else "Step 1/1"
        print(f"{C.BOLD}  {step_label} ▸ Extracting relationships → cluster-graph.json{C.RESET}")

        if not self.input_file.is_file():
            print(f"  {C.RED}✗ Input not found: {self.input_file}{C.RESET}")
            return False

        hash_before = self._file_hash(self.output_file)

        extract_cmd = [
            sys.executable, str(EXTRACT_SCRIPT),
            "--input", str(self.input_file),
            "--output", str(self.output_file),
            "--cache-dir", self.cache_dir,
        ]
        if self.nvd_api_key:
            extract_cmd.extend(["--nvd-api-key", self.nvd_api_key])

        if not self._run_subprocess_verbose(extract_cmd, "extract_relationships"):
            print(f"\n{C.RED}  ✗  Extraction failed.{C.RESET}")
            return False

        hash_after = self._file_hash(self.output_file)
        self._last_hash = hash_after

        print()
        summary = self._graph_summary()
        if hash_before is None:
            print(f"  {C.GREEN}✓ Graph CREATED ({summary}){C.RESET}")
        elif hash_before == hash_after:
            print(f"  {C.GREEN}✓ Graph unchanged ({summary}){C.RESET}")
        else:
            print(f"  {C.YELLOW}⚡ Graph UPDATED ({summary}){C.RESET}")

        return True

    def _run_cycle_compact(self) -> bool:
        """Subsequent runs — compact one-line-per-step output."""
        self._run_count += 1
        ts = datetime.now().strftime("%H:%M:%S")

        # Step 1: Collect (quiet)
        collect_ok = True
        collect_status = f"{C.YELLOW}SKIP{C.RESET}"
        if not self.skip_collect:
            collect_cmd = [
                sys.executable, str(COLLECT_SCRIPT),
                "--output", str(self.resources_dir),
            ]
            collect_ok, collect_err = self._run_subprocess_quiet(collect_cmd, "collect")
            if collect_ok:
                collect_status = f"{C.GREEN}OK{C.RESET}"
            else:
                collect_status = f"{C.RED}FAIL{C.RESET}"
                print(f"  {C.RED}[{ts}] Fetch #{self._run_count}  Collect: {collect_status}  — {collect_err}{C.RESET}")
                return False

        # Step 2: Extract (quiet)
        if not self.input_file.is_file():
            print(f"  {C.RED}[{ts}] Fetch #{self._run_count}  Collect: {collect_status}  Extract: {C.RED}FAIL{C.RESET} — input file missing")
            return False

        hash_before = self._file_hash(self.output_file)

        extract_cmd = [
            sys.executable, str(EXTRACT_SCRIPT),
            "--input", str(self.input_file),
            "--output", str(self.output_file),
            "--cache-dir", self.cache_dir,
        ]
        if self.nvd_api_key:
            extract_cmd.extend(["--nvd-api-key", self.nvd_api_key])

        extract_ok, extract_err = self._run_subprocess_quiet(extract_cmd, "extract")
        if not extract_ok:
            print(f"  {C.RED}[{ts}] Fetch #{self._run_count}  Collect: {collect_status}  Extract: {C.RED}FAIL{C.RESET} — {extract_err}")
            return False

        extract_status = f"{C.GREEN}OK{C.RESET}"

        # Change detection
        hash_after = self._file_hash(self.output_file)
        self._last_hash = hash_after

        summary = self._graph_summary()
        if hash_before is None:
            change_tag = f"{C.GREEN}CREATED{C.RESET}"
        elif hash_before == hash_after:
            change_tag = f"{C.DIM}NO CHANGE{C.RESET}"
        else:
            change_tag = f"{C.YELLOW}⚡ UPDATED{C.RESET}"

        # Print compact summary line
        print(f"  {C.CYAN}[{ts}]{C.RESET} Fetch #{self._run_count}  Collect: {collect_status}  Extract: {extract_status}  Graph: {change_tag}  ({summary})")

        return True

    def run(self) -> None:
        """Start the fetch loop. Blocks until KeyboardInterrupt (or runs once)."""
        self._print_banner()

        if self.run_once:
            self._run_cycle_verbose()
            print(f"\n{C.GREEN}{C.BOLD}  ✓  One-shot fetch complete.{C.RESET}")
            return

        print(f"{C.DIM}  Fetching every {self.interval}s — press Ctrl+C to stop.{C.RESET}\n")

        try:
            # First cycle: verbose so user sees full pipeline details
            self._run_cycle_verbose()
            print(f"\n{C.DIM}  💤 Sleeping {self.interval}s until next fetch...{C.RESET}")
            time.sleep(self.interval)

            # Subsequent cycles: compact one-liner logs
            while True:
                self._run_cycle_compact()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}{C.BOLD}  ⏹  Fetcher stopped.{C.RESET}")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fetcher.py",
        description="KubeAttackViz — Periodic Graph Fetcher (collect → extract loop)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fetcher.py                              # Collect + extract every 60s
  python fetcher.py --interval 30                # Every 30s
  python fetcher.py --skip-collect               # Only re-extract (no kubectl)
  python fetcher.py --once                       # Single run and exit
  python fetcher.py --input path/to/cluster.json --output path/to/graph.json
        """,
    )

    parser.add_argument(
        "--resources-dir",
        default=str(DEFAULT_RESOURCES),
        metavar="DIR",
        help=f"Output directory for collected resources (default: {DEFAULT_RESOURCES})",
    )
    parser.add_argument(
        "--input",
        default=str(DEFAULT_INPUT),
        metavar="PATH",
        help=f"Path to cluster.json input (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        metavar="PATH",
        help=f"Path for cluster-graph.json output (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        metavar="SECONDS",
        help=f"Fetch interval in seconds (default: {DEFAULT_INTERVAL})",
    )
    parser.add_argument(
        "--nvd-api-key",
        default=None,
        metavar="KEY",
        help="NVD API key for faster CVE lookups (default: $NVD_API_KEY env)",
    )
    parser.add_argument(
        "--cache-dir",
        default=DEFAULT_CACHE_DIR,
        metavar="DIR",
        help=f"NVD cache directory (default: {DEFAULT_CACHE_DIR})",
    )
    parser.add_argument(
        "--skip-collect",
        action="store_true",
        help="Skip collect_all_resources.py (only re-extract from existing cluster.json)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one collect+extract cycle and exit (no looping)",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    nvd_key = args.nvd_api_key or os.environ.get("NVD_API_KEY", "") or None

    fetcher = GraphFetcher(
        resources_dir=Path(args.resources_dir).resolve(),
        input_file=Path(args.input).resolve(),
        output_file=Path(args.output).resolve(),
        interval=args.interval,
        nvd_api_key=nvd_key,
        cache_dir=args.cache_dir,
        skip_collect=args.skip_collect,
        run_once=args.once,
    )
    fetcher.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
