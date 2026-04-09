# KubeAttackViz — Kubernetes Attack Path Visualizer

> A CLI tool that models your Kubernetes cluster as an attack graph and runs BFS / Dijkstra / DFS analysis to surface kill-chain risks, RBAC issues, and remediation steps.

---

## Quick Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Verify install
python main.py --help
```

**Requirements:** Python 3.10+, `networkx`, `typer[all]`, `rich`  
**Optional:** `kubectl` (for live cluster ingestion)

---

## Input Options

Every analysis command accepts one of two data sources:

| Flag | Description |
|------|-------------|
| `--input <file.json>` | Load a saved cluster graph JSON (offline) |
| `--kubectl` | Pull live state directly from the cluster |

> Use `--no-enrich` to skip real-time NIST NVD CVE lookups (offline mode).

---

## Analysis Commands

### `full-report` — Kill Chain Audit
```bash
# From JSON file
python main.py full-report --input cluster-graph.json

# From live cluster (saves to report.txt)
python main.py full-report --kubectl

# Save machine-readable JSON
python main.py full-report --kubectl --output-json audit.json
```

### `shortest-path` — Dijkstra Attack Path
```bash
python main.py shortest-path --input cluster-graph.json --source "web-frontend" --target "prod-database"

# Live cluster
python main.py shortest-path --kubectl --source "internet" --target "secret-db"
```

### `blast-radius` — BFS Reachability
```bash
python main.py blast-radius --input cluster-graph.json --source "web-frontend" --depth 4

# Live cluster, save output
python main.py blast-radius --kubectl --source "internet" --depth 4 -o radius.txt
```

### `cycles` — DFS Cycle Detection
```bash
python main.py cycles --input cluster-graph.json
```

### `critical-node` — Chokepoint Analysis
```bash
python main.py critical-node --input cluster-graph.json --top 5
```

### `rbac-audit` — RBAC Risk Scanner
```bash
python main.py rbac-audit --input cluster-graph.json

# Live cluster, save output
python main.py rbac-audit --kubectl --output rbac-audit.txt
```

### `node-risk` — Path Centrality Risk
```bash
python main.py node-risk --input cluster-graph.json --top 10

# Live cluster
python main.py node-risk --kubectl --top 10 --output risk-map.txt
```

### `classify` — Attack Path Classification
```bash
python main.py classify --input cluster-graph.json
```

### `explain` — Natural Language Path Explanation
```bash
python main.py explain --input cluster-graph.json --source "web-frontend" --target "prod-database"
```

---

## Data & Export Commands

### `export-graph` — Save Cluster Snapshot
```bash
# Bakes live CVE/CVSS scores into the JSON
python main.py export-graph --kubectl --output master-snapshot.json
```

### `export-frontend` — Generate D3.js Visualizer Data
```bash
python main.py export-frontend --input cluster-graph.json --output visualizer/graph-data.json

# From live cluster
python main.py export-frontend --kubectl --output visualizer/graph-data.json
```

### `diff` — Compare Two Snapshots
```bash
python main.py diff baseline.json current.json
```

### `dump-raw` — Raw Cluster State Dump
```bash
python main.py dump-raw --output raw-k8s-state.json
```

### `graph-info` — Graph Structure Summary
```bash
python main.py graph-info --input cluster-graph.json
```

---

## Run Tests

```bash
python main.py run-tests
```

Runs 13 built-in deterministic tests covering BFS, Dijkstra, DFS, critical-node, and severity scoring.

---

## D3.js Interactive Visualizer

```bash
# Step 1 — Generate frontend data
python main.py export-frontend --input cluster-graph.json --output visualizer/graph-data.json

# Step 2 — Serve the visualizer
cd visualizer
python -m http.server 8080

# Step 3 — Open in browser
# http://localhost:8080
```

---

## Common Workflows

### Offline analysis from a saved snapshot
```bash
python main.py full-report --input master-snapshot.json --output-json results.json
```

### Live cluster → snapshot → visualize
```bash
python main.py export-graph --kubectl --output snapshot.json
python main.py full-report --input snapshot.json
python main.py export-frontend --input snapshot.json --output visualizer/graph-data.json
cd visualizer && python -m http.server 8080
```

### Targeted path investigation
```bash
python main.py shortest-path --input snapshot.json --source "internet" --target "prod-database"
python main.py explain      --input snapshot.json --source "internet" --target "prod-database"
python main.py blast-radius --input snapshot.json --source "internet" --depth 5
```

---

## Command Summary

| Command | Purpose |
|---------|---------|
| `full-report` | Comprehensive kill-chain audit |
| `shortest-path` | Minimum-weight attack path (Dijkstra) |
| `blast-radius` | Reachable nodes from a source (BFS) |
| `cycles` | Privilege escalation loop detection (DFS) |
| `critical-node` | Find chokepoint nodes via graph surgery |
| `rbac-audit` | RBAC wildcard & escalation detection |
| `node-risk` | Risk amplification by path centrality |
| `classify` | Categorise paths (lateral move, cred theft…) |
| `explain` | Plain-English path narrative |
| `diff` | Detect security regressions between snapshots |
| `export-graph` | Persist cluster graph to JSON |
| `export-frontend` | Generate D3.js visualizer data |
| `dump-raw` | Raw kubectl state dump |
| `graph-info` | Node/edge/source/sink summary |
| `run-tests` | Run built-in test suite |
