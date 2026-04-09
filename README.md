# k8sShield

Production-grade Kubernetes attack path analysis and visualization platform.

k8sShield collects live cluster state, builds an enriched attack graph, runs security and graph analytics, detects RBAC risk patterns, tracks temporal changes, and serves an interactive visualization for investigation.

## What k8sShield Covers

- Cluster-wide Kubernetes resource collection using kubectl
- Relationship extraction from resources into an attack graph
- CVE-aware risk enrichment for exposed software/components
- Attack path analysis with BFS, DFS, and Dijkstra-based workflows
- RBAC misconfiguration and privilege-escalation risk analysis
- Temporal snapshotting and graph diffing over time
- Optional Neo4j export for historical and graph-native querying
- Frontend graph export and local interactive D3.js visualization

## High-Level Architecture

1. Collection layer
- Pulls Kubernetes resources from the active kubectl context
- Produces a normalized cluster snapshot

2. Extraction layer
- Converts raw resources into nodes and edges
- Builds cluster-graph.json with security-relevant relationships

3. Analysis layer
- Runs path, cycle, blast-radius, and critical-node analytics
- Generates human-readable report output

4. Monitoring layer
- Watches for graph changes
- Produces temporal diffs and optional Neo4j updates

5. Visualization layer
- Exports frontend-ready graph data
- Serves an analyst-friendly D3.js dashboard

## Repository Layout

- main.py: Root orchestrator CLI (single primary entry point)
- fetcher.py: Periodic collect+extract loop
- watcher.py: File watcher for temporal diff and optional Neo4j export
- extractor/: Collection and relationship extraction modules
- post_extraction/: Analysis engine, algorithms, and CLI
- post_extraction/visualizer/: Web visualization assets
- test-cases/: Deterministic graph test datasets

## Prerequisites

- Python 3.10+
- kubectl configured against a reachable Kubernetes cluster
- Optional: Neo4j (for temporal persistence/export)
- Optional: NVD API key (for faster CVE enrichment)

## Installation

```bash
pip install -r post_extraction/requirements.txt
pip install requests
```

## Quick Start

Run everything end-to-end (recommended):

```bash
python main.py run
```

Typical production-style local run with custom interval:

```bash
python main.py run --interval 30 --server-port 8080 --no-neo4j
```

## Important Commands

Run these from the project root unless noted.

### Core pipeline commands

```bash
# Full orchestrated workflow (pipeline + fetcher + watcher + frontend server)
python main.py run --interval 30

# One-shot pipeline execution (collect -> extract -> visualize -> report)
python main.py pipeline

# Collection only
python main.py collect

# Relationship extraction only
python main.py extract

# Generate report only
python main.py report

# Export frontend graph data only
python main.py visualize

# Temporal watcher (without Neo4j)
python main.py watch --no-neo4j

# Periodic fetch loop
python main.py fetch --interval 30
```

### Important analysis commands

Run these from post_extraction/ when working directly with analysis.

```bash
cd post_extraction

# Comprehensive security report from existing graph
python main.py full-report --input ../cluster-graph.json

# Highest-risk shortest path between two points
python main.py shortest-path --input ../cluster-graph.json --source "internet" --target "prod-db"

# Reachability/blast-radius from a source
python main.py blast-radius --input ../cluster-graph.json --source "internet" --depth 4

# RBAC audit
python main.py rbac-audit --input ../cluster-graph.json

# Built-in deterministic tests
python main.py run-tests
```

## Key Outputs

- extractor/k8s_resources/cluster.json: Raw collected cluster snapshot
- cluster-graph.json: Enriched attack graph (nodes, edges, scores)
- report.txt: Human-readable security findings and path analysis
- post_extraction/visualizer/graph-data.json: Frontend-ready graph payload
- .temporal_snapshots/: Historical snapshots for temporal analysis

## Neo4j Integration (Optional)

Enable Neo4j in watcher mode when persistent graph history is required:

```bash
python main.py watch --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-pass <password>
```

## Recommended Operational Workflow

1. Validate cluster context in kubectl.
2. Execute python main.py run --interval 30 for continuous operation.
3. Review report.txt and visualizer output after each cycle.
4. Use targeted analysis commands (shortest-path, blast-radius, rbac-audit) for deep investigations.
5. Enable Neo4j when historical trend analysis is required.

## Security and Usage Notes

- Run against authorized clusters only.
- Protect generated graph/report artifacts if they contain sensitive topology data.
- Avoid exposing local visualization/Neo4j endpoints publicly without access controls.

