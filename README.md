# KubeAttackViz — Kubernetes Attack Path Visualizer

> A full-stack Kubernetes security analysis platform that collects live cluster state, models it as an attack graph, runs kill-chain algorithms (BFS / Dijkstra / DFS), detects RBAC risks, tracks changes over time via temporal snapshots, and visualises everything in an interactive D3.js dashboard — all from a single command.

---

## Architecture Overview

```
root-folder/
│
├── main.py                  ← ★ THE SINGLE ENTRY POINT (pipeline orchestrator)
├── fetcher.py               ← Periodic collect+extract cron daemon
├── watcher.py               ← File-change watcher → temporal diff + Neo4j export
│
├── extractor/
│   ├── collect_all_resources.py   ← kubectl collector (Step 1)
│   └── extract_relationships.py   ← Graph builder + CVE enricher (Step 2)
│
└── post_extraction/               ← Analysis & visualisation engine
    ├── main.py              ← CLI entry point for the analysis engine
    ├── visualizer/          ← D3.js interactive frontend
    └── kube_attack_viz/     ← Core Python package
        ├── cli.py           ← Typer CLI commands
        ├── temporal.py      ← Snapshot store, diff engine, Neo4j exporter
        ├── algorithms/      ← BFS, Dijkstra, DFS, critical-node
        ├── rbac_analyzer.py ← RBAC risk detection
        └── ...
```

**Data flow:**

```
kubectl → collect_all_resources.py → cluster.json
                                           ↓
                          extract_relationships.py → cluster-graph.json
                                                           ↓
                          post_extraction/main.py → report.txt + graph-data.json
                                                           ↓
                                         watcher.py → Neo4j + temporal diffs
```

---

## Quick Setup

### 1. Prerequisites

| Requirement | Notes |
|-------------|-------|
| Python 3.10+ | Required |
| `kubectl` | Configured and pointing at a live cluster |
| Neo4j (optional) | For temporal graph persistence |
| NIST NVD API Key (optional) | For faster CVE lookups — [get one free](https://nvd.nist.gov/developers/request-an-api-key) |

### 2. Install dependencies

```bash
# Core analysis engine
pip install -r post_extraction/requirements.txt

# Pipeline extras (CVE enrichment)
pip install requests
```

**`post_extraction/requirements.txt` includes:**
- `networkx>=3.1` — graph algorithms
- `typer[all]>=0.9.0` — CLI framework
- `rich>=13.0.0` — terminal output
- `neo4j>=5.0.0` — temporal graph export

### 3. Verify install

```bash
python main.py --help
```

---

## Getting Started

### Option A — All-in-one (recommended)

Runs the full pipeline, then starts the fetcher + watcher + frontend server in parallel. **One command to rule them all.**

```bash
python main.py run
```

With customisations:
```bash
python main.py run --interval 30 --server-port 8080 --no-neo4j
```

### Option B — One-shot pipeline run

```bash
python main.py pipeline
```

Skip re-collection if `cluster.json` already exists:
```bash
python main.py pipeline --skip-collect
```

### Option C — Analysis from an existing JSON snapshot

```bash
# Run full security report from a saved snapshot
cd post_extraction
python main.py full-report --input ../cluster-graph.json
```

---

## Key Commands

> All commands below are run from the **project root** (`deleteme-p/`) unless otherwise noted.
> For the exhaustive reference, see [COMMANDS.md](./COMMANDS.md).

### Pipeline commands (root `main.py`)

| Command | What it does |
|---------|--------------|
| `python main.py run` | Full pipeline + fetcher + watcher + frontend server |
| `python main.py pipeline` | One-shot: collect → extract → visualize → report |
| `python main.py collect` | Step 1 only — query `kubectl` and save `cluster.json` |
| `python main.py extract` | Step 2 only — build `cluster-graph.json` with CVE scores |
| `python main.py visualize` | Generate frontend `graph-data.json` |
| `python main.py report` | Generate `report.txt` security report |
| `python main.py watch` | Start temporal watcher (diff + Neo4j export on file change) |
| `python main.py fetch` | Start periodic fetcher loop (collect + extract every N seconds) |

### Analysis commands (`post_extraction/main.py`)

Run from inside the `post_extraction/` directory, or use the orchestrator's `report` / `visualize` commands above.

```bash
cd post_extraction

# Comprehensive kill-chain audit
python main.py full-report --input ../cluster-graph.json

# Find the most dangerous attack path between two nodes
python main.py shortest-path --input ../cluster-graph.json --source "internet" --target "prod-db"

# How far can an attacker reach from a given node?
python main.py blast-radius --input ../cluster-graph.json --source "web-frontend" --depth 4

# Detect privilege escalation cycles
python main.py cycles --input ../cluster-graph.json

# Identify chokepoint nodes
python main.py critical-node --input ../cluster-graph.json --top 5

# RBAC misconfiguration scan
python main.py rbac-audit --input ../cluster-graph.json

# Run built-in test suite (13 deterministic tests)
python main.py run-tests
```

### Frontend visualiser

```bash
# Step 1 — generate frontend data (if not done via pipeline)
cd post_extraction
python main.py export-frontend --input ../cluster-graph.json

# Step 2 — serve it
cd visualizer
python -m http.server 8080
# open http://localhost:8080
```

---

## Temporal Analysis & Neo4j

The watcher continuously monitors `cluster-graph.json` for changes, diffs snapshots, and exports results to Neo4j:

```bash
# Start watcher (Neo4j disabled)
python main.py watch --no-neo4j

# Start watcher with Neo4j
python main.py watch --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-pass secret

# View snapshot history
cd post_extraction
python main.py temporal-history

# Manually capture a snapshot and diff against the last one
python main.py temporal-snapshot --input ../cluster-graph.json
```

---

## Setting Up a Test Cluster

Sample Kubernetes manifests are provided in `extractor/creating-cluster/` to spin up a realistic multi-namespace cluster with intentional misconfigurations:

```bash
cd extractor/creating-cluster
bash apply-all.sh
```

Then run the full pipeline against it:
```bash
cd ../..
python main.py pipeline
```

---

## Common Workflows

### Full offline analysis from a saved snapshot
```bash
cd post_extraction
python main.py full-report --input ../cluster-graph.json --output-json results.json
```

### Live cluster → snapshot → report → visualise
```bash
python main.py pipeline
# Opens: post_extraction/visualizer/index.html
```

### Continuous live monitoring with 30-second refresh
```bash
python main.py run --interval 30 --no-neo4j
```

### Targeted path investigation
```bash
cd post_extraction
python main.py shortest-path --input ../cluster-graph.json --source "internet" --target "prod-db"
python main.py explain      --input ../cluster-graph.json --source "internet" --target "prod-db"
python main.py blast-radius --input ../cluster-graph.json --source "internet" --depth 5
```

---

## Output Files

| File | Description |
|------|-------------|
| `extractor/k8s_resources/cluster.json` | Raw kubectl dump of all resources |
| `cluster-graph.json` | Enriched attack graph (nodes + edges + CVE scores) |
| `report.txt` | Human-readable kill-chain security report |
| `post_extraction/visualizer/graph-data.json` | D3.js frontend data |
| `.temporal_snapshots/` | Persistent snapshot history for temporal diffing |

---

> For the full command reference including every flag, see **[COMMANDS.md](./COMMANDS.md)**.
