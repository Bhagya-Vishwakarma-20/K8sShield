#!/usr/bin/env python3
"""
KubeAttackViz — Unified Pipeline Orchestrator
═══════════════════════════════════════════════

Streamlines the entire Kubernetes attack-path analysis workflow
into a single entry point:

  Step 1 ▸ Collect all K8s resources from the live cluster   (extractor/collect_all_resources.py)
  Step 2 ▸ Extract relationships & build the cluster graph    (extractor/extract_relationships.py)
  Step 3 ▸ Export frontend visualization + generate report    (post_extraction/main.py → CLI)

Usage
─────
  # ★ Run EVERYTHING with one command (pipeline + fetcher + watcher)
  python main.py run
  python main.py run --interval 30

  # Run the full pipeline end-to-end (one-shot)
  python main.py pipeline

  # Start the periodic fetcher (collect + extract cron job)
  python main.py fetch                         # Collect+extract every 60s
  python main.py fetch --interval 30           # Every 30s
  python main.py fetch --skip-collect          # Only re-extract

  # Start the temporal file watcher
  python main.py watch
  python main.py watch --interval 30
  python main.py watch --no-neo4j

  # Run individual stages
  python main.py collect                       # Step 1 only
  python main.py extract                       # Step 2 only
  python main.py visualize                     # Step 3a — frontend export
  python main.py report                        # Step 3b — full report

  # Skip collection (reuse existing cluster.json)
  python main.py pipeline --skip-collect

  # Specify custom paths
  python main.py pipeline --resources-dir my_resources --graph-output my-graph.json
"""

import argparse
import multiprocessing
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime

# ─── Paths ────────────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent
EXTRACTOR_DIR = ROOT_DIR / "extractor"
POST_EXTRACTION_DIR = ROOT_DIR / "post_extraction"

COLLECT_SCRIPT = EXTRACTOR_DIR / "collect_all_resources.py"
EXTRACT_SCRIPT = EXTRACTOR_DIR / "extract_relationships.py"
KUBER_MAIN = POST_EXTRACTION_DIR / "main.py"

DEFAULT_RESOURCES_DIR = EXTRACTOR_DIR / "k8s_resources"
DEFAULT_CLUSTER_JSON = DEFAULT_RESOURCES_DIR / "cluster.json"
DEFAULT_GRAPH_JSON = ROOT_DIR / "cluster-graph.json"
DEFAULT_REPORT_OUTPUT = ROOT_DIR / "report.txt"
DEFAULT_FRONTEND_OUTPUT = POST_EXTRACTION_DIR / "visualizer" / "graph-data.json"

# ─── ANSI helpers ─────────────────────────────────────────────────────────────
class C:
    HEADER = "\033[95m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


def banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════════╗
║              🛡️  KubeAttackViz — Unified Pipeline              ║
╚══════════════════════════════════════════════════════════════════╝{C.RESET}
""")


def step_header(step_num: int, total: int, title: str):
    print()
    print(f"{C.BOLD}{C.BLUE}{'─' * 70}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}  STEP {step_num}/{total} ▸ {title}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}{'─' * 70}{C.RESET}")
    print()


def success(msg: str):
    print(f"{C.GREEN}{C.BOLD}  ✓ {msg}{C.RESET}")


def fail(msg: str):
    print(f"{C.RED}{C.BOLD}  ✗ {msg}{C.RESET}")


def info(msg: str):
    print(f"{C.DIM}  ℹ {msg}{C.RESET}")


def warn(msg: str):
    print(f"{C.YELLOW}  ⚠ {msg}{C.RESET}")


# ─── Step runners ─────────────────────────────────────────────────────────────

def run_step(cmd: list, cwd: str, step_name: str) -> bool:
    """Run a subprocess, streaming output. Returns True on success."""
    info(f"Running: {' '.join(str(c) for c in cmd)}")
    info(f"Working dir: {cwd}")
    print()
    try:
        result = subprocess.run(
            [sys.executable] + [str(c) for c in cmd],
            cwd=str(cwd),
            timeout=600,  # 10 minute timeout
        )
        if result.returncode == 0:
            success(f"{step_name} completed successfully.")
            return True
        else:
            fail(f"{step_name} failed with exit code {result.returncode}.")
            return False
    except subprocess.TimeoutExpired:
        fail(f"{step_name} timed out (600s limit).")
        return False
    except FileNotFoundError:
        fail(f"Python interpreter not found. Ensure Python is installed.")
        return False
    except Exception as e:
        fail(f"{step_name} error: {e}")
        return False


def step_collect(resources_dir: str) -> bool:
    """Step 1: Collect K8s resources from the live cluster."""
    cmd = [COLLECT_SCRIPT, "--output", resources_dir]
    return run_step(cmd, cwd=str(EXTRACTOR_DIR), step_name="Collect Resources")


def step_extract(input_file: str, output_file: str, nvd_api_key: str = None, cache_dir: str = None) -> bool:
    """Step 2: Extract relationships and build cluster graph."""
    cmd = [EXTRACT_SCRIPT, "--input", input_file, "--output", output_file]
    if nvd_api_key:
        cmd.extend(["--nvd-api-key", nvd_api_key])
    if cache_dir:
        cmd.extend(["--cache-dir", cache_dir])
    return run_step(cmd, cwd=str(EXTRACTOR_DIR), step_name="Extract Relationships")


def step_visualize(graph_file: str, frontend_output: str = None) -> bool:
    """Step 3a: Export frontend visualization data."""
    cmd = [KUBER_MAIN, "export-frontend", "--input", graph_file]
    if frontend_output:
        cmd.extend(["--output", frontend_output])
    return run_step(cmd, cwd=str(POST_EXTRACTION_DIR), step_name="Export Frontend")


def step_report(graph_file: str, report_output: str = None, report_json: str = None) -> bool:
    """Step 3b: Generate the full security report."""
    cmd = [KUBER_MAIN, "full-report", "--input", graph_file]
    if report_output:
        cmd.extend(["--output", report_output])
    if report_json:
        cmd.extend(["--output-json", report_json])
    return run_step(cmd, cwd=str(POST_EXTRACTION_DIR), step_name="Full Report")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="KubeAttackViz — Unified Pipeline Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py pipeline                              # Full end-to-end pipeline
  python main.py pipeline --skip-collect               # Skip kubectl collection
  python main.py collect                               # Step 1 only
  python main.py extract                               # Step 2 only
  python main.py visualize                             # Step 3a only
  python main.py report                                # Step 3b only
  python main.py watch                                 # Temporal watcher
  python main.py pipeline --nvd-api-key YOUR_KEY       # Use NVD API key for faster CVE lookups
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # ── pipeline ──
    p_pipeline = subparsers.add_parser(
        "pipeline",
        help="Run the full pipeline: collect → extract → visualize + report",
    )
    p_pipeline.add_argument("--skip-collect", action="store_true",
                            help="Skip Step 1 (reuse existing cluster.json)")
    p_pipeline.add_argument("--skip-extract", action="store_true",
                            help="Skip Step 2 (reuse existing cluster-graph.json)")
    p_pipeline.add_argument("--resources-dir", default=str(DEFAULT_RESOURCES_DIR),
                            help=f"Output directory for collected resources (default: {DEFAULT_RESOURCES_DIR})")
    p_pipeline.add_argument("--cluster-json", default=str(DEFAULT_CLUSTER_JSON),
                            help=f"Path to cluster.json (default: {DEFAULT_CLUSTER_JSON})")
    p_pipeline.add_argument("--graph-output", default=str(DEFAULT_GRAPH_JSON),
                            help=f"Path for cluster-graph.json output (default: {DEFAULT_GRAPH_JSON})")
    p_pipeline.add_argument("--report-output", default=str(DEFAULT_REPORT_OUTPUT),
                            help=f"Path for the text report (default: {DEFAULT_REPORT_OUTPUT})")
    p_pipeline.add_argument("--report-json", default=None,
                            help="Path for the JSON report (optional)")
    p_pipeline.add_argument("--frontend-output", default=str(DEFAULT_FRONTEND_OUTPUT),
                            help=f"Path for frontend graph data (default: {DEFAULT_FRONTEND_OUTPUT})")
    p_pipeline.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY", ""),
                            help="NVD API key for faster CVE lookups (default: $NVD_API_KEY env)")
    p_pipeline.add_argument("--cache-dir", default=str(EXTRACTOR_DIR / ".nvd_cache"),
                            help="NVD cache directory")

    # ── collect ──
    p_collect = subparsers.add_parser("collect", help="Step 1: Collect K8s resources from the cluster")
    p_collect.add_argument("--resources-dir", default=str(DEFAULT_RESOURCES_DIR),
                           help=f"Output directory (default: {DEFAULT_RESOURCES_DIR})")

    # ── extract ──
    p_extract = subparsers.add_parser("extract", help="Step 2: Extract relationships & build cluster graph")
    p_extract.add_argument("--cluster-json", default=str(DEFAULT_CLUSTER_JSON),
                           help=f"Input cluster.json path (default: {DEFAULT_CLUSTER_JSON})")
    p_extract.add_argument("--graph-output", default=str(DEFAULT_GRAPH_JSON),
                           help=f"Output graph JSON path (default: {DEFAULT_GRAPH_JSON})")
    p_extract.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY", ""),
                           help="NVD API key")
    p_extract.add_argument("--cache-dir", default=str(EXTRACTOR_DIR / ".nvd_cache"),
                           help="NVD cache directory")

    # ── visualize ──
    p_viz = subparsers.add_parser("visualize", help="Step 3a: Export frontend visualization")
    p_viz.add_argument("--graph-input", default=str(DEFAULT_GRAPH_JSON),
                       help=f"Input graph JSON path (default: {DEFAULT_GRAPH_JSON})")
    p_viz.add_argument("--frontend-output", default=str(DEFAULT_FRONTEND_OUTPUT),
                       help=f"Output frontend JSON path (default: {DEFAULT_FRONTEND_OUTPUT})")

    # ── report ──
    p_report = subparsers.add_parser("report", help="Step 3b: Generate full security report")
    p_report.add_argument("--graph-input", default=str(DEFAULT_GRAPH_JSON),
                          help=f"Input graph JSON path (default: {DEFAULT_GRAPH_JSON})")
    p_report.add_argument("--report-output", default=str(DEFAULT_REPORT_OUTPUT),
                          help=f"Output report path (default: {DEFAULT_REPORT_OUTPUT})")
    p_report.add_argument("--report-json", default=None,
                          help="Path for the JSON report (optional)")

    # ── watch ──
    p_watch = subparsers.add_parser(
        "watch",
        help="Start the temporal graph watcher (monitors cluster-graph.json for changes)",
    )
    p_watch.add_argument(
        "--graph",
        default=str(DEFAULT_GRAPH_JSON),
        metavar="PATH",
        help=f"Path to cluster-graph.json to watch (default: {DEFAULT_GRAPH_JSON})",
    )
    p_watch.add_argument(
        "--interval",
        type=int,
        default=15,
        metavar="SECONDS",
        help="Polling interval in seconds (default: 15)",
    )
    p_watch.add_argument(
        "--persist-dir",
        default=str(ROOT_DIR / ".temporal_snapshots"),
        metavar="DIR",
        help="Directory to persist snapshot history (default: .temporal_snapshots)",
    )
    p_watch.add_argument(
        "--neo4j-uri",
        default=None,
        metavar="URI",
        help="Neo4j URI for automatic diff export (e.g. bolt://localhost:7687)",
    )
    p_watch.add_argument(
        "--neo4j-user",
        default="neo4j",
        metavar="USER",
        help="Neo4j username (default: neo4j)",
    )
    p_watch.add_argument(
        "--neo4j-pass",
        default="password",
        metavar="PASS",
        help="Neo4j password",
    )
    p_watch.add_argument(
        "--no-neo4j",
        action="store_true",
        help="Disable Neo4j export (diff-and-alert only)",
    )
    p_watch.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )

    # ── fetch ──
    p_fetch = subparsers.add_parser(
        "fetch",
        help="Start the periodic fetcher (collect + extract cron job)",
    )
    p_fetch.add_argument(
        "--interval",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Fetch interval in seconds (default: 60)",
    )
    p_fetch.add_argument(
        "--resources-dir",
        default=str(DEFAULT_RESOURCES_DIR),
        metavar="DIR",
        help=f"Output directory for collected resources (default: {DEFAULT_RESOURCES_DIR})",
    )
    p_fetch.add_argument(
        "--cluster-json",
        default=str(DEFAULT_CLUSTER_JSON),
        metavar="PATH",
        help=f"Path to cluster.json (default: {DEFAULT_CLUSTER_JSON})",
    )
    p_fetch.add_argument(
        "--graph-output",
        default=str(DEFAULT_GRAPH_JSON),
        metavar="PATH",
        help=f"Path for cluster-graph.json output (default: {DEFAULT_GRAPH_JSON})",
    )
    p_fetch.add_argument(
        "--nvd-api-key",
        default=os.environ.get("NVD_API_KEY", ""),
        metavar="KEY",
        help="NVD API key for faster CVE lookups (default: $NVD_API_KEY env)",
    )
    p_fetch.add_argument(
        "--cache-dir",
        default=str(EXTRACTOR_DIR / ".nvd_cache"),
        metavar="DIR",
        help="NVD cache directory",
    )
    p_fetch.add_argument(
        "--skip-collect",
        action="store_true",
        help="Skip collect_all_resources.py (only re-extract)",
    )
    p_fetch.add_argument(
        "--once",
        action="store_true",
        help="Run one collect+extract cycle and exit (no looping)",
    )

    # ── run (all-in-one) ──
    p_run = subparsers.add_parser(
        "run",
        help="★ Run the full pipeline, then start fetcher + watcher in parallel",
    )
    p_run.add_argument(
        "--skip-collect",
        action="store_true",
        help="Skip initial collection (reuse existing cluster.json)",
    )
    p_run.add_argument(
        "--skip-extract",
        action="store_true",
        help="Skip initial extraction (reuse existing cluster-graph.json)",
    )
    p_run.add_argument(
        "--resources-dir",
        default=str(DEFAULT_RESOURCES_DIR),
        metavar="DIR",
        help=f"Resources directory (default: {DEFAULT_RESOURCES_DIR})",
    )
    p_run.add_argument(
        "--cluster-json",
        default=str(DEFAULT_CLUSTER_JSON),
        metavar="PATH",
        help=f"Path to cluster.json (default: {DEFAULT_CLUSTER_JSON})",
    )
    p_run.add_argument(
        "--graph-output",
        default=str(DEFAULT_GRAPH_JSON),
        metavar="PATH",
        help=f"Path for cluster-graph.json output (default: {DEFAULT_GRAPH_JSON})",
    )
    p_run.add_argument(
        "--report-output",
        default=str(DEFAULT_REPORT_OUTPUT),
        metavar="PATH",
        help=f"Report output path (default: {DEFAULT_REPORT_OUTPUT})",
    )
    p_run.add_argument(
        "--report-json",
        default=None,
        help="JSON report output path (optional)",
    )
    p_run.add_argument(
        "--frontend-output",
        default=str(DEFAULT_FRONTEND_OUTPUT),
        metavar="PATH",
        help=f"Frontend output path (default: {DEFAULT_FRONTEND_OUTPUT})",
    )
    p_run.add_argument(
        "--nvd-api-key",
        default=os.environ.get("NVD_API_KEY", ""),
        metavar="KEY",
        help="NVD API key for CVE lookups",
    )
    p_run.add_argument(
        "--cache-dir",
        default=str(EXTRACTOR_DIR / ".nvd_cache"),
        metavar="DIR",
        help="NVD cache directory",
    )
    p_run.add_argument(
        "--interval",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Interval in seconds for both fetcher and watcher (default: 60)",
    )
    p_run.add_argument(
        "--no-neo4j",
        action="store_true",
        help="Disable Neo4j export in watcher",
    )
    p_run.add_argument(
        "--persist-dir",
        default=str(ROOT_DIR / ".temporal_snapshots"),
        metavar="DIR",
        help="Snapshot persistence directory",
    )
    p_run.add_argument(
        "--server-port",
        type=int,
        default=8000,
        metavar="PORT",
        help="Port for the HTTP server to serve the frontend (default: 8000)",
    )
    p_run.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )

    return parser


def cmd_pipeline(args):
    """Run the full pipeline."""
    banner()
    start_time = time.time()
    total_steps = 4
    current_step = 0
    results = {}

    # ── Step 1: Collect ──
    current_step += 1
    if args.skip_collect:
        step_header(current_step, total_steps, "Collect K8s Resources  [SKIPPED]")
        warn("Skipping collection — using existing cluster.json")
        results["collect"] = "skipped"
    else:
        step_header(current_step, total_steps, "Collect K8s Resources")
        ok = step_collect(args.resources_dir)
        results["collect"] = "success" if ok else "failed"
        if not ok:
            fail("Collection failed. Cannot proceed.")
            fail("Make sure kubectl is configured and a cluster is accessible.")
            return 1

    # ── Step 2: Extract ──
    current_step += 1
    if args.skip_extract:
        step_header(current_step, total_steps, "Extract Relationships  [SKIPPED]")
        warn("Skipping extraction — using existing cluster-graph.json")
        results["extract"] = "skipped"
    else:
        step_header(current_step, total_steps, "Extract Relationships & Build Graph")
        # Verify input exists
        if not Path(args.cluster_json).is_file():
            fail(f"cluster.json not found at: {args.cluster_json}")
            fail("Run 'collect' first or provide --cluster-json path.")
            return 1
        ok = step_extract(args.cluster_json, args.graph_output, args.nvd_api_key, args.cache_dir)
        results["extract"] = "success" if ok else "failed"
        if not ok:
            fail("Extraction failed. Cannot proceed to analysis.")
            return 1

    # Verify graph file exists before analysis steps
    graph_path = args.graph_output
    if not Path(graph_path).is_file():
        fail(f"cluster-graph.json not found at: {graph_path}")
        fail("Run 'extract' first or provide --graph-output path.")
        return 1

    # ── Step 3: Visualize ──
    current_step += 1
    step_header(current_step, total_steps, "Export Frontend Visualization")
    ok = step_visualize(graph_path, args.frontend_output)
    results["visualize"] = "success" if ok else "failed"
    if not ok:
        warn("Frontend export failed, but continuing to report generation...")

    # ── Step 4: Report ──
    current_step += 1
    step_header(current_step, total_steps, "Generate Full Security Report")
    ok = step_report(graph_path, args.report_output, args.report_json)
    results["report"] = "success" if ok else "failed"

    # ── Summary ──
    elapsed = time.time() - start_time
    print()
    print(f"{C.BOLD}{C.CYAN}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  PIPELINE SUMMARY{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═' * 70}{C.RESET}")
    print()

    status_icons = {"success": f"{C.GREEN}✓{C.RESET}", "failed": f"{C.RED}✗{C.RESET}", "skipped": f"{C.YELLOW}⊘{C.RESET}"}
    steps_info = [
        ("Collect Resources", "collect"),
        ("Extract Relationships", "extract"),
        ("Frontend Visualization", "visualize"),
        ("Full Security Report", "report"),
    ]
    for label, key in steps_info:
        status = results.get(key, "skipped")
        icon = status_icons.get(status, "?")
        print(f"  {icon}  {label:<30} {status}")

    print()
    print(f"  {C.DIM}Time elapsed: {elapsed:.1f}s{C.RESET}")
    print()

    # Output locations
    print(f"  {C.BOLD}Output Files:{C.RESET}")
    if results.get("collect") == "success":
        print(f"    • Resources:  {args.resources_dir}")
    if results.get("extract") in ("success", "skipped"):
        print(f"    • Graph:      {graph_path}")
    if results.get("visualize") == "success":
        print(f"    • Frontend:   {args.frontend_output}")
        viz_index = POST_EXTRACTION_DIR / "visualizer" / "index.html"
        if viz_index.is_file():
            print(f"    • Visualizer: {viz_index}")
    if results.get("report") == "success":
        print(f"    • Report:     {args.report_output}")
        if args.report_json:
            print(f"    • Report JSON:{args.report_json}")

    print()
    print(f"{C.BOLD}{C.CYAN}{'═' * 70}{C.RESET}")

    # Return non-zero if any critical step failed
    if results.get("extract") == "failed" or results.get("collect") == "failed":
        return 1
    return 0


def cmd_collect(args):
    """Run collection only."""
    banner()
    step_header(1, 1, "Collect K8s Resources")
    ok = step_collect(args.resources_dir)
    return 0 if ok else 1


def cmd_extract(args):
    """Run extraction only."""
    banner()
    step_header(1, 1, "Extract Relationships & Build Graph")
    if not Path(args.cluster_json).is_file():
        fail(f"Input not found: {args.cluster_json}")
        fail("Run 'python main.py collect' first.")
        return 1
    ok = step_extract(args.cluster_json, args.graph_output, args.nvd_api_key, args.cache_dir)
    return 0 if ok else 1


def cmd_visualize(args):
    """Run frontend export only."""
    banner()
    step_header(1, 1, "Export Frontend Visualization")
    if not Path(args.graph_input).is_file():
        fail(f"Graph file not found: {args.graph_input}")
        fail("Run 'python main.py extract' first.")
        return 1
    ok = step_visualize(args.graph_input, args.frontend_output)
    return 0 if ok else 1


def cmd_watch(args):
    """Start the temporal graph watcher by delegating to watcher.py."""
    watcher_script = ROOT_DIR / "watcher.py"
    if not watcher_script.is_file():
        fail(f"watcher.py not found at: {watcher_script}")
        return 1

    cmd = [watcher_script, "--graph", args.graph, "--interval", str(args.interval),
            "--persist-dir", args.persist_dir, "--log-level", args.log_level]

    if args.no_neo4j:
        cmd.append("--no-neo4j")
    elif args.neo4j_uri:
        cmd.extend(["--neo4j-uri", args.neo4j_uri,
                     "--neo4j-user", args.neo4j_user,
                     "--neo4j-pass", args.neo4j_pass])

    info(f"Starting watcher: {' '.join(str(c) for c in cmd)}")
    try:
        subprocess.run([sys.executable] + [str(c) for c in cmd])
    except KeyboardInterrupt:
        pass  # watcher handles its own Ctrl+C
    return 0


def cmd_report(args):
    """Run report generation only."""
    banner()
    step_header(1, 1, "Generate Full Security Report")
    if not Path(args.graph_input).is_file():
        fail(f"Graph file not found: {args.graph_input}")
        fail("Run 'python main.py extract' first.")
        return 1
    ok = step_report(args.graph_input, args.report_output, args.report_json)
    return 0 if ok else 1


def cmd_fetch(args):
    """Start the periodic fetcher (collect → extract cron job)."""
    fetcher_script = ROOT_DIR / "fetcher.py"
    if not fetcher_script.is_file():
        fail(f"fetcher.py not found at: {fetcher_script}")
        return 1

    cmd = [
        fetcher_script,
        "--resources-dir", args.resources_dir,
        "--input", args.cluster_json,
        "--output", args.graph_output,
        "--interval", str(args.interval),
        "--cache-dir", args.cache_dir,
    ]
    if args.nvd_api_key:
        cmd.extend(["--nvd-api-key", args.nvd_api_key])
    if args.skip_collect:
        cmd.append("--skip-collect")
    if args.once:
        cmd.append("--once")

    info(f"Starting fetcher: {' '.join(str(c) for c in cmd)}")
    try:
        subprocess.run([sys.executable] + [str(c) for c in cmd])
    except KeyboardInterrupt:
        pass
    return 0


# ─── run: all-in-one (pipeline + fetcher + watcher) ──────────────────────────

def _run_fetcher_process(args_dict: dict) -> None:
    """Entry point for the fetcher subprocess (used by cmd_run)."""
    fetcher_script = ROOT_DIR / "fetcher.py"
    cmd = [
        sys.executable, str(fetcher_script),
        "--resources-dir", args_dict["resources_dir"],
        "--input", args_dict["cluster_json"],
        "--output", args_dict["graph_output"],
        "--interval", str(args_dict["interval"]),
        "--cache-dir", args_dict["cache_dir"],
    ]
    if args_dict.get("nvd_api_key"):
        cmd.extend(["--nvd-api-key", args_dict["nvd_api_key"]])
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass


def _run_watcher_process(args_dict: dict) -> None:
    """Entry point for the watcher subprocess (used by cmd_run)."""
    watcher_script = ROOT_DIR / "watcher.py"
    cmd = [
        sys.executable, str(watcher_script),
        "--graph", args_dict["graph_output"],
        "--interval", str(args_dict["interval"]),
        "--persist-dir", args_dict["persist_dir"],
        "--log-level", args_dict["log_level"],
    ]
    if args_dict.get("no_neo4j"):
        cmd.append("--no-neo4j")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass


def _run_server_process(args_dict: dict) -> None:
    """Entry point for the frontend HTTP server subprocess (used by cmd_run)."""
    api_script = POST_EXTRACTION_DIR / "visualizer" / "api.py"
    cmd = [
        sys.executable, str(api_script),
        "--port", str(args_dict["server_port"]),
        "--snapshots-dir", args_dict.get("persist_dir", str(ROOT_DIR / ".temporal_snapshots")),
    ]
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass


def cmd_run(args):
    """
    ★ The all-in-one command:
      1. Run the full pipeline once (collect → extract → visualize → report)
      2. Start the fetcher cron job (collect + extract every N seconds)
      3. Start the watcher (temporal diff on graph changes)
      4. Serve the frontend visualizer on the specified port.
    All run concurrently. Ctrl+C stops everything.
    """
    banner()
    print(f"{C.BOLD}{C.CYAN}  ★  ALL-IN-ONE MODE  ★{C.RESET}")
    print(f"{C.DIM}  Pipeline → Fetcher + Watcher (every {args.interval}s) → Server (:{args.server_port}){C.RESET}")
    print()

    # ── Phase 1: Run the pipeline once ────────────────────────────────────
    print(f"{C.BOLD}{C.CYAN}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  PHASE 1 ▸ Initial Pipeline Run{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═' * 70}{C.RESET}")

    # Build a namespace that looks like pipeline args
    class PipelineArgs:
        pass
    pa = PipelineArgs()
    pa.skip_collect = args.skip_collect
    pa.skip_extract = args.skip_extract
    pa.resources_dir = args.resources_dir
    pa.cluster_json = args.cluster_json
    pa.graph_output = args.graph_output
    pa.report_output = args.report_output
    pa.report_json = args.report_json
    pa.frontend_output = args.frontend_output
    pa.nvd_api_key = args.nvd_api_key
    pa.cache_dir = args.cache_dir

    pipeline_result = cmd_pipeline(pa)
    if pipeline_result != 0:
        warn("Initial pipeline had failures, but continuing with fetcher + watcher...")

    # ── Phase 2: Start fetcher + watcher in parallel ──────────────────────
    print()
    print(f"{C.BOLD}{C.CYAN}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  PHASE 2 ▸ Starting Fetcher + Watcher{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═' * 70}{C.RESET}")
    print()
    print(f"  {C.GREEN}🔄  Fetcher:{C.RESET} collect + extract every {args.interval}s")
    print(f"  {C.GREEN}🔭  Watcher:{C.RESET} temporal diff every {args.interval}s")
    print(f"  {C.GREEN}🌐  Server:{C.RESET}  http://localhost:{args.server_port}")
    print(f"\n{C.DIM}  Press Ctrl+C to stop all.{C.RESET}\n")

    # Serialize args to a dict for the subprocesses
    shared_args = {
        "resources_dir": args.resources_dir,
        "cluster_json": args.cluster_json,
        "graph_output": args.graph_output,
        "interval": args.interval,
        "nvd_api_key": args.nvd_api_key,
        "cache_dir": args.cache_dir,
        "persist_dir": args.persist_dir,
        "log_level": args.log_level,
        "no_neo4j": args.no_neo4j,
        "server_port": args.server_port,
    }

    fetcher_proc = multiprocessing.Process(
        target=_run_fetcher_process, args=(shared_args,), name="fetcher"
    )
    watcher_proc = multiprocessing.Process(
        target=_run_watcher_process, args=(shared_args,), name="watcher"
    )
    server_proc = multiprocessing.Process(
        target=_run_server_process, args=(shared_args,), name="server"
    )

    fetcher_proc.start()
    watcher_proc.start()
    server_proc.start()

    try:
        fetcher_proc.join()
        watcher_proc.join()
        server_proc.join()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}{C.BOLD}  ⏹  Stopping fetcher + watcher + server...{C.RESET}")
        fetcher_proc.terminate()
        watcher_proc.terminate()
        server_proc.terminate()
        fetcher_proc.join(timeout=5)
        watcher_proc.join(timeout=5)
        server_proc.join(timeout=5)
        print(f"{C.GREEN}{C.BOLD}  ✓  All processes stopped.{C.RESET}")

    return 0


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        banner()
        parser.print_help()
        print()
        print(f"{C.YELLOW}  Tip: Run 'python main.py run' to launch the entire system in one command.{C.RESET}")
        print(f"{C.YELLOW}       Run 'python main.py pipeline' for a one-shot pipeline run.{C.RESET}")
        print(f"{C.YELLOW}       Run 'python main.py fetch' to start the periodic fetcher.{C.RESET}")
        print(f"{C.YELLOW}       Run 'python main.py watch' to start the temporal graph watcher.{C.RESET}")
        print()
        return 0

    dispatch = {
        "pipeline":  cmd_pipeline,
        "collect":   cmd_collect,
        "extract":   cmd_extract,
        "visualize": cmd_visualize,
        "report":    cmd_report,
        "watch":     cmd_watch,
        "fetch":     cmd_fetch,
        "run":       cmd_run,
    }

    handler = dispatch.get(args.command)
    if handler:
        return handler(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
