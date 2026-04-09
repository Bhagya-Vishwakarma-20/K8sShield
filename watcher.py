#!/usr/bin/env python3
"""
watcher.py — Temporal Graph Watcher for KubeAttackViz
══════════════════════════════════════════════════════

Monitors cluster-graph.json for changes, diffs snapshots using the
temporal analysis engine, prints structured alerts, and triggers
Neo4j export automatically when structural differences are detected.

Design Goals:
  • Zero external dependencies — pure stdlib polling (no watchdog needed).
  • Content-hash deduplication — avoids false positives from mtime-only changes.
  • SnapshotStore persistence — history survives process restarts.
  • Additive — does not modify any existing module.

Usage:
  python watcher.py                          # Default: watch cluster-graph.json, 15s interval
  python watcher.py --interval 30            # Poll every 30 seconds
  python watcher.py --graph path/to/graph.json
  python watcher.py --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-pass secret
  python watcher.py --persist-dir .my_snapshots
  python watcher.py --log-level DEBUG

Stop with Ctrl+C.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ─── Path bootstrap ──────────────────────────────────────────────────────────
# Ensure the post_extraction package is importable regardless of CWD
_ROOT = Path(__file__).resolve().parent
_POST_EXTRACTION = _ROOT / "post_extraction"
if str(_POST_EXTRACTION) not in sys.path:
    sys.path.insert(0, str(_POST_EXTRACTION))

# ─── Windows UTF-8 fix ───────────────────────────────────────────────────────
# Force UTF-8 output on Windows to avoid charmap errors with Unicode characters.
import io as _io
if hasattr(sys.stdout, "buffer"):
    sys.stdout = _io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "buffer"):
    sys.stderr = _io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from kube_attack_viz.ingestion import ingest_from_json
from kube_attack_viz.temporal import (
    Snapshot,
    SnapshotStore,
    diff_snapshots,
    format_temporal_diff,
    format_alert_summary,
    format_snapshot_history,
    Neo4jExporter,
)

# ─── Defaults ────────────────────────────────────────────────────────────────
DEFAULT_GRAPH_PATH   = _ROOT / "cluster-graph.json"
DEFAULT_INTERVAL     = 15          # seconds between polls
DEFAULT_PERSIST_DIR  = _ROOT / ".temporal_snapshots"
DEFAULT_NEO4J_URI    = os.getenv("NEO4J_URI", "")
DEFAULT_NEO4J_USER   = os.getenv("NEO4J_USER", "")
DEFAULT_NEO4J_PASS   = os.getenv("NEO4J_PASSWORD", "")

# ─── ANSI helpers ─────────────────────────────────────────────────────────────
class C:
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


# ─── Logging setup ───────────────────────────────────────────────────────────
def _setup_logging(level: str) -> logging.Logger:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        level=getattr(logging, level.upper(), logging.INFO),
    )
    return logging.getLogger("kubeattackviz.watcher")


# ─── Core Watcher ────────────────────────────────────────────────────────────

class GraphWatcher:
    """
    Polls cluster-graph.json for changes and fires the temporal diff pipeline.

    State machine:
      STARTUP  → seed the SnapshotStore with the current file (if present).
      POLLING  → check mtime + content hash every `interval` seconds.
      CHANGED  → diff old vs new snapshot, emit alerts, optionally export to Neo4j.
    """

    def __init__(
        self,
        graph_path: Path,
        interval: int,
        persist_dir: Path,
        neo4j_uri: str | None,
        neo4j_user: str,
        neo4j_pass: str,
        logger: logging.Logger,
    ):
        self.graph_path  = graph_path
        self.interval    = interval
        self.store       = SnapshotStore(persist_dir=persist_dir)
        self.neo4j_uri   = neo4j_uri
        self.neo4j_user  = neo4j_user
        self.neo4j_pass  = neo4j_pass
        self.log         = logger

        # Tracks the last seen content hash to avoid duplicate processing
        self._last_hash: str | None = None

    # ── Public ───────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Start the polling loop. Blocks until KeyboardInterrupt."""
        self._print_banner()
        self._seed()

        self.log.info(f"Watching: {self.graph_path}  (interval={self.interval}s)")
        print(f"\n{C.DIM}  Polling every {self.interval}s — press Ctrl+C to stop.{C.RESET}\n")

        try:
            while True:
                self._poll()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}{C.BOLD}  ⏹  Watcher stopped.{C.RESET}")
            self.log.info("Watcher stopped by user.")

    # ── Private ──────────────────────────────────────────────────────────────

    def _print_banner(self) -> None:
        print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════════╗
║         🔭  KubeAttackViz — Temporal Graph Watcher             ║
╚══════════════════════════════════════════════════════════════════╝{C.RESET}
  Graph file : {self.graph_path}
  Persist dir: {self.store._persist_dir or '(in-memory only)'}
  Neo4j      : {self.neo4j_uri or '(disabled)'}
  Snapshots  : {self.store.count} stored on disk
""")

    def _read_file_hash(self) -> str | None:
        """Return the SHA-256 hex digest of the graph file, or None if missing/unreadable."""
        try:
            content = self.graph_path.read_bytes()
            return hashlib.sha256(content).hexdigest()
        except (FileNotFoundError, OSError):
            return None

    def _load_snapshot(self) -> Snapshot | None:
        """Ingest the current graph file and wrap it in a Snapshot."""
        try:
            cluster = ingest_from_json(self.graph_path)
            snap = Snapshot.from_cluster(
                cluster,
                source=f"json:{self.graph_path}",
                metadata={"watched_at": datetime.now(timezone.utc).isoformat()},
            )
            return snap
        except FileNotFoundError:
            self.log.warning(f"Graph file not found: {self.graph_path}")
            return None
        except Exception as exc:
            self.log.error(f"Failed to load graph: {exc}")
            return None

    def _seed(self) -> None:
        """
        On startup, read the current file as the baseline snapshot.

        If a previous snapshot already exists in the store (from a prior run),
        we skip seeding so history is preserved and the *next* pipeline run
        will trigger a real diff against the stored baseline.
        """
        current_hash = self._read_file_hash()
        if current_hash is None:
            print(f"{C.YELLOW}  ⚠  Graph file not found at startup. Waiting for it to appear...{C.RESET}")
            return

        self._last_hash = current_hash

        if self.store.count == 0:
            # First ever run — seed with current file
            snap = self._load_snapshot()
            if snap:
                self.store.add(snap)
                self._enrich_snapshot_with_frontend_data(snap)
                print(f"{C.GREEN}  ✓  Baseline snapshot captured (first run).{C.RESET}")
                print(f"     ID: {snap.snapshot_id}  Hash: {snap.graph_hash}")
        else:
            latest = self.store.latest
            print(f"{C.GREEN}  ✓  Resuming from existing snapshot history ({self.store.count} snapshots).{C.RESET}")
            print(f"     Latest: {latest.snapshot_id}  ({latest.timestamp})")
            # Update last hash to the stored baseline's hash so we detect
            # the diff between what was last stored and the current file.
            if latest.graph_hash != current_hash[:16]:
                # File has changed since last seen — process the difference now
                self.log.info("Graph file differs from last stored snapshot — processing diff immediately.")
                self._process_change()

    def _poll(self) -> None:
        """One polling tick: check if the file has changed."""
        current_hash = self._read_file_hash()
        if current_hash is None:
            # File gone (pipeline in-progress write, or deleted)
            return

        if current_hash == self._last_hash:
            ts = datetime.now().strftime("%H:%M:%S")
            self.log.debug("No change detected.")
            print(f"  {C.DIM}[{ts}] Watch — graph unchanged, no diff needed{C.RESET}", flush=True)
            return

        self.log.info(f"Change detected (hash: {current_hash[:16]})")
        self._last_hash = current_hash
        self._process_change()

    def _format_compact_diff(self, diff) -> str:
        """Build a compact one-line change summary from a TemporalDiff."""
        parts = []
        if diff.new_nodes:
            parts.append(f"{C.GREEN}+{len(diff.new_nodes)} nodes{C.RESET}")
        if diff.removed_nodes:
            parts.append(f"{C.RED}-{len(diff.removed_nodes)} nodes{C.RESET}")
        if diff.new_edges:
            parts.append(f"{C.GREEN}+{len(diff.new_edges)} edges{C.RESET}")
        if diff.removed_edges:
            parts.append(f"{C.RED}-{len(diff.removed_edges)} edges{C.RESET}")
        if diff.new_attack_paths:
            parts.append(f"{C.RED}+{len(diff.new_attack_paths)} attack paths{C.RESET}")
        if diff.removed_attack_paths:
            parts.append(f"{C.GREEN}-{len(diff.removed_attack_paths)} attack paths{C.RESET}")
        if diff.alerts:
            crit = sum(1 for a in diff.alerts if a.severity == "CRITICAL")
            high = sum(1 for a in diff.alerts if a.severity == "HIGH")
            if crit:
                parts.append(f"{C.RED}{C.BOLD}{crit} CRITICAL alerts{C.RESET}")
            if high:
                parts.append(f"{C.YELLOW}{high} HIGH alerts{C.RESET}")
            rest = len(diff.alerts) - crit - high
            if rest:
                parts.append(f"{rest} other alerts")
        return " | ".join(parts) if parts else "no structural changes"

    def _process_change(self) -> None:
        """Load new snapshot, diff against previous, alert, and export."""
        ts_display = datetime.now().strftime("%H:%M:%S")

        old_snap = self.store.latest
        new_snap = self._load_snapshot()

        if new_snap is None:
            print(f"  {C.RED}[{ts_display}] Watch — could not load snapshot, skipping{C.RESET}")
            return

        # Quick hash check via graph_hash (16-char prefix)
        if old_snap.graph_hash == new_snap.graph_hash:
            self.store.add(new_snap)
            print(f"  {C.DIM}[{ts_display}] Watch — change detected but no structural diff | Neo4j: skipped{C.RESET}")
            return

        # ── Compute diff ──────────────────────────────────────────────────
        try:
            diff = diff_snapshots(old_snap, new_snap)
        except Exception as exc:
            self.log.error(f"Diff computation failed: {exc}", exc_info=True)
            print(f"  {C.RED}[{ts_display}] Watch — diff failed: {exc}{C.RESET}")
            self.store.add(new_snap)
            return

        # ── Annotate snapshot metadata ────────────────────────────────────
        changes_list = []
        for nid, name, ntype in diff.new_nodes:
            changes_list.append(f"+{name} ({ntype})")
        for nid, name, ntype in diff.removed_nodes:
            changes_list.append(f"-{name} ({ntype})")
        for path in diff.new_attack_paths:
            changes_list.append(f"+Path: {' → '.join(path.path_names[:2])}...")
        
        # Keep only the top 5 to avoid giant tooltips
        if len(changes_list) > 5:
            remaining = len(changes_list) - 5
            changes_list = changes_list[:5] + [f"...+{remaining} more"]
            
        new_snap.metadata["changes"] = changes_list
        self.store.add(new_snap)



        # ── Compact change summary ────────────────────────────────────────
        change_summary = self._format_compact_diff(diff)

        # ── Neo4j export ──────────────────────────────────────────────────
        neo4j_status = self._export_to_neo4j_compact(diff, old_snap, new_snap)

        # ── Print compact log line ────────────────────────────────────────
        print(f"  {C.YELLOW}[{ts_display}] Watch — {C.BOLD}CHANGES DETECTED{C.RESET}{C.YELLOW} | {change_summary} | Neo4j: {neo4j_status}{C.RESET}")

        # Print individual new node/edge names on separate lines for context
        for nid, name, ntype in diff.new_nodes:
            print(f"           {C.GREEN}+ {ntype}: {name}{C.RESET}")
        for nid, name, ntype in diff.removed_nodes:
            print(f"           {C.RED}- {ntype}: {name}{C.RESET}")
        for path in diff.new_attack_paths:
            print(f"           {C.RED}⚠ New attack path: {' → '.join(path.path_names)}{C.RESET}")

        # ── Auto-rerun post-extraction steps ──────────────────────────────
        if diff.has_changes:
            self._rerun_post_extraction(ts_display)
            self._enrich_snapshot_with_frontend_data(new_snap)

    def _enrich_snapshot_with_frontend_data(self, snap: Snapshot) -> None:
        """Injects the fully computed frontend graph data into the stored snapshot."""
        frontend_file = _POST_EXTRACTION / "visualizer" / "graph-data.json"
        if not frontend_file.exists():
            return
        
        try:
            with open(frontend_file, "r", encoding="utf-8") as f:
                enriched = json.load(f)
            
            # Replace the raw graph entirely with the fully enriched backend computation
            # This ensures nodes have `is_source`/`is_sink`, and edges have `cvss` scores!
            snap.cluster_data = enriched
                    
            # Overwrite the snapshot JSON on disk with the fully enriched one
            self.store._persist_snapshot(snap)
        except Exception as e:
            self.log.error(f"Failed to enrich snapshot with attack paths: {e}")

    def _rerun_post_extraction(self, ts_display: str) -> None:
        """Re-run visualize + report steps after a structural change is detected."""
        graph_path = self.graph_path
        kuber_main = _POST_EXTRACTION / "main.py"
        frontend_output = _POST_EXTRACTION / "visualizer" / "graph-data.json"
        report_output = _ROOT / "report.txt"

        if not kuber_main.is_file():
            self.log.warning(f"post_extraction/main.py not found at {kuber_main}, skipping re-run.")
            return

        print(f"  {C.CYAN}[{ts_display}] Watch — re-running post-extraction (visualize + report)…{C.RESET}")

        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}

        # Export frontend visualization
        try:
            result = subprocess.run(
                [sys.executable, str(kuber_main), "export-frontend",
                 "--input", str(graph_path), "--output", str(frontend_output)],
                cwd=str(_POST_EXTRACTION),
                capture_output=True, text=True, timeout=120,
                env=env, encoding="utf-8", errors="replace"
            )
            if result.returncode == 0:
                print(f"           {C.GREEN}✓ Frontend re-exported → {frontend_output.name}{C.RESET}")
            else:
                self.log.error(f"Frontend export stderr: {result.stderr[:300]}")
        except Exception as exc:
            self.log.error(f"Frontend export error: {exc}")

        # Generate report
        try:
            result = subprocess.run(
                [sys.executable, str(kuber_main), "full-report",
                 "--input", str(graph_path), "--output", str(report_output)],
                cwd=str(_POST_EXTRACTION),
                capture_output=True, text=True, timeout=120,
                env=env, encoding="utf-8", errors="replace"
            )
            if result.returncode == 0:
                print(f"           {C.GREEN}✓ Report re-generated → {report_output.name}{C.RESET}")
            else:
                self.log.error(f"Report stderr: {result.stderr[:300]}")
        except Exception as exc:
            self.log.error(f"Report error: {exc}")

    def _export_to_neo4j_compact(self, diff, old_snap: Snapshot, new_snap: Snapshot) -> str:
        """Push the diff graph into Neo4j and return a compact status string."""
        if not diff.has_changes:
            return f"{C.DIM}skipped (no changes){C.RESET}"

        if not self.neo4j_uri:
            return f"{C.DIM}disabled{C.RESET}"

        try:
            exporter = Neo4jExporter(
                uri=self.neo4j_uri,
                user=self.neo4j_user,
                password=self.neo4j_pass,
            )
            exporter.ensure_constraints()
            stats = exporter.export_diff(diff, old_snap, new_snap)
            exporter.close()
            self.log.info(f"Neo4j export stats: {stats}")
            return f"{C.GREEN}sent ✓{C.RESET}"
        except ImportError:
            return f"{C.YELLOW}neo4j pkg missing{C.RESET}"
        except Exception as exc:
            self.log.error(f"Neo4j export error: {exc}", exc_info=True)
            return f"{C.RED}FAILED ({exc}){C.RESET}"

    def _export_to_neo4j(self, diff, old_snap: Snapshot, new_snap: Snapshot) -> None:
        """Push the diff graph into Neo4j."""
        if not self.neo4j_uri:
            self.log.debug("Neo4j export disabled (no URI configured).")
            print(f"{C.DIM}  ℹ  Neo4j export skipped (--neo4j-uri not set).{C.RESET}")
            return

        print(f"\n{C.CYAN}  ⬆  Exporting diff to Neo4j: {self.neo4j_uri}{C.RESET}")
        try:
            exporter = Neo4jExporter(
                uri=self.neo4j_uri,
                user=self.neo4j_user,
                password=self.neo4j_pass,
            )
            exporter.ensure_constraints()
            stats = exporter.export_diff(diff, old_snap, new_snap)
            exporter.close()
            print(f"{C.GREEN}  ✓  Neo4j export complete: {stats}{C.RESET}")
            self.log.info(f"Neo4j export stats: {stats}")
        except ImportError:
            print(f"{C.YELLOW}  ⚠  neo4j package not installed. Run: pip install neo4j{C.RESET}")
        except Exception as exc:
            print(f"{C.RED}  ✗  Neo4j export failed: {exc}{C.RESET}")
            self.log.error(f"Neo4j export error: {exc}", exc_info=True)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="watcher.py",
        description="KubeAttackViz — Temporal Graph Watcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python watcher.py                                    # Watch with defaults
  python watcher.py --interval 30                      # Poll every 30s
  python watcher.py --graph /path/to/cluster-graph.json
  python watcher.py --neo4j-uri bolt://localhost:7687 \\
                    --neo4j-user neo4j --neo4j-pass secret
  python watcher.py --persist-dir .my_snapshots
        """,
    )

    parser.add_argument(
        "--graph",
        default=str(DEFAULT_GRAPH_PATH),
        metavar="PATH",
        help=f"Path to cluster-graph.json to watch (default: {DEFAULT_GRAPH_PATH})",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        metavar="SECONDS",
        help=f"Polling interval in seconds (default: {DEFAULT_INTERVAL})",
    )
    parser.add_argument(
        "--persist-dir",
        default=str(DEFAULT_PERSIST_DIR),
        metavar="DIR",
        help=f"Directory to persist snapshot history (default: {DEFAULT_PERSIST_DIR})",
    )
    parser.add_argument(
        "--neo4j-uri",
        default=DEFAULT_NEO4J_URI,
        metavar="URI",
        help=f"Neo4j bolt/neo4j URI (default: {DEFAULT_NEO4J_URI})",
    )
    parser.add_argument(
        "--neo4j-user",
        default=DEFAULT_NEO4J_USER,
        metavar="USER",
        help=f"Neo4j username (default: {DEFAULT_NEO4J_USER})",
    )
    parser.add_argument(
        "--neo4j-pass",
        default=DEFAULT_NEO4J_PASS,
        metavar="PASS",
        help="Neo4j password",
    )
    parser.add_argument(
        "--no-neo4j",
        action="store_true",
        help="Disable Neo4j export even if URI is set",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    logger = _setup_logging(args.log_level)

    graph_path = Path(args.graph).resolve()
    persist_dir = Path(args.persist_dir).resolve()
    neo4j_uri = None if args.no_neo4j else args.neo4j_uri

    watcher = GraphWatcher(
        graph_path=graph_path,
        interval=args.interval,
        persist_dir=persist_dir,
        neo4j_uri=neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_pass=args.neo4j_pass,
        logger=logger,
    )
    watcher.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
