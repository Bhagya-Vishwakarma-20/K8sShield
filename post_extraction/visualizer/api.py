#!/usr/bin/env python3
"""
KubeAttackViz — Visualizer API Server
═══════════════════════════════════════

Lightweight HTTP server that:
  1. Serves the static visualizer files (index.html, styles.css, script.js, etc.)
  2. Exposes /api/snapshots   — returns snapshot index for the timeline
  3. Exposes /api/snapshots/<id> — returns a single snapshot's graph data
  4. Exposes /api/graph-data  — returns current graph-data.json with cache headers

Usage:
  python api.py                       # Serve on :8000
  python api.py --port 9000           # Custom port
  python api.py --snapshots-dir /path/to/.temporal_snapshots
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import sys
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from datetime import datetime, timezone

# ─── Defaults ────────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent           # visualizer/
_PROJECT_ROOT = _ROOT.parent.parent               # Main/
DEFAULT_SNAPSHOTS_DIR = _PROJECT_ROOT / ".temporal_snapshots"
DEFAULT_PORT = 8000


class VisualizerHandler(BaseHTTPRequestHandler):
    """Handle static files + JSON API requests."""

    snapshots_dir: Path = DEFAULT_SNAPSHOTS_DIR
    static_dir: Path = _ROOT

    def log_message(self, format, *args):
        """Compact log format."""
        ts = datetime.now().strftime("%H:%M:%S")
        sys.stderr.write(f"  [API {ts}] {args[0]}\n")

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json_response(self, data: dict | list, status: int = 200):
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _error_json(self, status: int, message: str):
        self._json_response({"error": message}, status=status)

    def _serve_file(self, file_path: Path):
        if not file_path.is_file():
            self.send_error(404, f"Not found: {file_path.name}")
            return
        content_type, _ = mimetypes.guess_type(str(file_path))
        content_type = content_type or "application/octet-stream"
        body = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if file_path.name == "graph-data.json":
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    # ── Routing ──────────────────────────────────────────────────────────────

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors_headers()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]  # strip query params

        # API routes
        if path == "/api/snapshots":
            return self._handle_snapshot_index()
        if path.startswith("/api/snapshots/"):
            snap_id = path.split("/api/snapshots/")[1].strip("/")
            return self._handle_snapshot_detail(snap_id)
        if path == "/api/graph-data":
            return self._serve_file(self.static_dir / "graph-data.json")

        # Static files
        if path == "/" or path == "":
            path = "/index.html"

        # Prevent directory traversal
        safe_path = Path(path.lstrip("/"))
        file_path = (self.static_dir / safe_path).resolve()
        if not str(file_path).startswith(str(self.static_dir.resolve())):
            self.send_error(403, "Forbidden")
            return

        self._serve_file(file_path)

    # ── API Handlers ─────────────────────────────────────────────────────────

    def _handle_snapshot_index(self):
        """Return the snapshot index with enriched metadata."""
        index_path = self.snapshots_dir / "snapshot_index.json"
        if not index_path.is_file():
            return self._json_response({"count": 0, "snapshots": []})

        try:
            with open(index_path, "r", encoding="utf-8") as f:
                index_data = json.load(f)

            # Enrich each snapshot with summary stats if snapshot file exists
            enriched = []
            for snap_entry in index_data.get("snapshots", []):
                snap_file = self.snapshots_dir / f"{snap_entry['snapshot_id']}.json"
                entry = {
                    "snapshot_id": snap_entry["snapshot_id"],
                    "timestamp": snap_entry["timestamp"],
                    "graph_hash": snap_entry.get("graph_hash", ""),
                    "source": snap_entry.get("source", ""),
                    "changes": snap_entry.get("changes", []),
                }
                if snap_file.is_file():
                    try:
                        with open(snap_file, "r", encoding="utf-8") as sf:
                            snap_data = json.load(sf)
                        cluster = snap_data.get("cluster_data", {})
                        entry["node_count"] = len(cluster.get("nodes", []))
                        entry["edge_count"] = len(cluster.get("edges", []))
                    except Exception:
                        pass
                enriched.append(entry)

            return self._json_response({
                "count": len(enriched),
                "updated_at": index_data.get("updated_at", ""),
                "snapshots": enriched,
            })
        except Exception as e:
            return self._error_json(500, str(e))

    def _handle_snapshot_detail(self, snap_id: str):
        """Return a single snapshot's cluster_data formatted for the frontend."""
        snap_file = self.snapshots_dir / f"{snap_id}.json"
        if not snap_file.is_file():
            return self._error_json(404, f"Snapshot not found: {snap_id}")

        try:
            with open(snap_file, "r", encoding="utf-8") as f:
                snap_data = json.load(f)

            cluster = snap_data.get("cluster_data", {})
            # Return the cluster data in frontend-compatible format
            result = {
                "snapshot_id": snap_data.get("snapshot_id", snap_id),
                "timestamp": snap_data.get("timestamp", ""),
                "graph_hash": snap_data.get("graph_hash", ""),
                "source": snap_data.get("source", ""),
                "nodes": cluster.get("nodes", []),
                "edges": cluster.get("edges", []),
                "metadata": {
                    "tool": "KubeAttackViz",
                    "version": "2.0.0",
                    "snapshot_view": True,
                    "generated_at": snap_data.get("timestamp", ""),
                },
                # Snapshot cluster_data may not have pre-computed analysis —
                # provide empty defaults for the frontend
                "attack_paths": cluster.get("attack_paths", []),
                "cycles": cluster.get("cycles", []),
                "critical_node": cluster.get("critical_node", {"baseline_paths": 0, "top_nodes": []}),
                "blast_radius": cluster.get("blast_radius", []),
                "graph_summary": cluster.get("graph_summary", {}),
            }
            return self._json_response(result)
        except Exception as e:
            return self._error_json(500, str(e))


def run_server(port: int = DEFAULT_PORT, snapshots_dir: str | Path = DEFAULT_SNAPSHOTS_DIR):
    """Start the visualizer API server."""
    VisualizerHandler.snapshots_dir = Path(snapshots_dir).resolve()
    VisualizerHandler.static_dir = _ROOT

    server = HTTPServer(("0.0.0.0", port), VisualizerHandler)
    print(f"\n  🌐  KubeAttackViz Visualizer — http://localhost:{port}")
    print(f"  📁  Static dir:    {_ROOT}")
    print(f"  📸  Snapshots dir: {snapshots_dir}")
    print(f"  📡  API endpoints:")
    print(f"       GET /api/snapshots      — timeline index")
    print(f"       GET /api/snapshots/<id> — snapshot detail")
    print(f"       GET /api/graph-data     — current graph\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  ⏹  Server stopped.")
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KubeAttackViz Visualizer Server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})")
    parser.add_argument("--snapshots-dir", default=str(DEFAULT_SNAPSHOTS_DIR),
                        help=f"Snapshots directory (default: {DEFAULT_SNAPSHOTS_DIR})")
    args = parser.parse_args()
    run_server(port=args.port, snapshots_dir=args.snapshots_dir)
