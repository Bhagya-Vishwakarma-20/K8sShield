# 📖 KubeAttackViz — Full Command Reference

> **All commands are run from the project root (`deleteme-p/`) unless a different directory is specified.**
> Internal scripts (`fetcher.py`, `watcher.py`, `extractor/` scripts) are called automatically by the orchestrator, but can also be invoked directly.

---

## Table of Contents

1. [Orchestrator — `main.py` (root)](#1-orchestrator--mainpy-root)
2. [Analysis CLI — `post_extraction/main.py`](#2-analysis-cli--post_extractionmainpy)
3. [Watcher — `watcher.py`](#3-watcher--watcherpy)
4. [Fetcher — `fetcher.py`](#4-fetcher--fetcherpy)
5. [extractor Scripts](#5-extractor-scripts)
6. [Global Flags Reference](#6-global-flags-reference)

---

## 1. Orchestrator — `main.py` (root)

The top-level entry point. Coordinates all pipeline stages and background daemons.

```
python main.py <command> [options]
```

---

### `run` ⭐ All-in-one

Runs the full pipeline once, then starts **fetcher + watcher + HTTP server** in parallel. Press `Ctrl+C` to stop all.

```bash
python main.py run
python main.py run --interval 30             # Refresh every 30s (fetcher + watcher)
python main.py run --no-neo4j                # Disable Neo4j export in watcher
python main.py run --server-port 9000        # Serve frontend on port 9000
python main.py run --skip-collect            # Skip initial kubectl collection
python main.py run --skip-extract            # Skip initial graph extraction
python main.py run --nvd-api-key YOUR_KEY    # Faster CVE lookups
```

| Flag | Default | Description |
|------|---------|-------------|
| `--interval SECONDS` | `60` | Interval for fetcher and watcher polling |
| `--no-neo4j` | `false` | Disable Neo4j export |
| `--server-port PORT` | `8000` | Port for the D3.js HTTP server |
| `--skip-collect` | `false` | Skip Step 1 (reuse existing `cluster.json`) |
| `--skip-extract` | `false` | Skip Step 2 (reuse existing `cluster-graph.json`) |
| `--resources-dir DIR` | `extractor/k8s_resources` | Where to store raw kubectl output |
| `--cluster-json PATH` | `extractor/k8s_resources/cluster.json` | Input for extraction step |
| `--graph-output PATH` | `cluster-graph.json` | Output attack graph JSON |
| `--report-output PATH` | `report.txt` | Output text report |
| `--report-json PATH` | *(none)* | Optional JSON report output |
| `--frontend-output PATH` | `post_extraction/visualizer/graph-data.json` | D3.js data file |
| `--nvd-api-key KEY` | `$NVD_API_KEY` env | NVD API key for CVE enrichment |
| `--cache-dir DIR` | `extractor/.nvd_cache` | NVD response cache directory |
| `--persist-dir DIR` | `.temporal_snapshots` | Snapshot persistence directory |
| `--log-level LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

---

### `pipeline` — One-shot full pipeline

Runs all 4 steps sequentially and exits.

```bash
python main.py pipeline
python main.py pipeline --skip-collect                      # Reuse existing cluster.json
python main.py pipeline --skip-extract                      # Reuse existing cluster-graph.json
python main.py pipeline --nvd-api-key YOUR_KEY              # With CVE enrichment
python main.py pipeline --report-json audit.json            # Also save JSON report
python main.py pipeline --resources-dir ./my_resources      # Custom output dir
python main.py pipeline --graph-output ./my-graph.json      # Custom graph path
```

Steps executed:
1. **collect** — `extractor/collect_all_resources.py`
2. **extract** — `extractor/extract_relationships.py`
3. **visualize** — `post_extraction/main.py export-frontend`
4. **report** — `post_extraction/main.py full-report`

---

### `collect` — Step 1 only

```bash
python main.py collect
python main.py collect --resources-dir ./my_resources
```

Calls `extractor/collect_all_resources.py` and saves per-namespace JSON files + a combined `cluster.json`.

---

### `extract` — Step 2 only

```bash
python main.py extract
python main.py extract --cluster-json ./path/to/cluster.json
python main.py extract --graph-output ./my-graph.json
python main.py extract --nvd-api-key YOUR_KEY
```

Calls `extractor/extract_relationships.py` to parse `cluster.json`, query NVD for CVEs, and produce `cluster-graph.json`.

---

### `visualize` — Step 3a only

```bash
python main.py visualize
python main.py visualize --graph-input ./cluster-graph.json
python main.py visualize --frontend-output post_extraction/visualizer/graph-data.json
```

Exports the graph as `graph-data.json` for the D3.js frontend.

---

### `report` — Step 3b only

```bash
python main.py report
python main.py report --graph-input ./cluster-graph.json
python main.py report --report-output ./report.txt
python main.py report --report-json ./report.json
```

Runs the full kill-chain report against the provided graph file.

---

### `watch` — Temporal watcher

Monitors `cluster-graph.json` for changes (content-hash based). On change: diffs snapshots, emits alerts, and optionally exports to Neo4j.

```bash
python main.py watch
python main.py watch --interval 30
python main.py watch --no-neo4j
python main.py watch --graph ./my-graph.json
python main.py watch --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-pass secret
python main.py watch --persist-dir ./.my_snapshots
python main.py watch --log-level DEBUG
```

| Flag | Default | Description |
|------|---------|-------------|
| `--graph PATH` | `cluster-graph.json` | File to watch |
| `--interval SECONDS` | `15` | Polling interval |
| `--persist-dir DIR` | `.temporal_snapshots` | Snapshot storage |
| `--neo4j-uri URI` | *(none)* | Neo4j bolt URI (disables export if empty) |
| `--neo4j-user USER` | `neo4j` | Neo4j username |
| `--neo4j-pass PASS` | `password` | Neo4j password |
| `--no-neo4j` | `false` | Explicitly disable Neo4j export |
| `--log-level LEVEL` | `INFO` | Logging verbosity |

---

### `fetch` — Periodic fetcher

Runs the `collect → extract` cycle on a fixed interval (cron-style).

```bash
python main.py fetch
python main.py fetch --interval 30
python main.py fetch --skip-collect             # Only re-extract (no kubectl)
python main.py fetch --once                     # One cycle, then exit
python main.py fetch --nvd-api-key YOUR_KEY
```

| Flag | Default | Description |
|------|---------|-------------|
| `--interval SECONDS` | `60` | Fetch interval |
| `--skip-collect` | `false` | Skip `collect_all_resources.py` |
| `--once` | `false` | Run a single cycle and exit |
| `--resources-dir DIR` | `extractor/k8s_resources` | kubectl output directory |
| `--cluster-json PATH` | `extractor/k8s_resources/cluster.json` | Input for extraction |
| `--graph-output PATH` | `cluster-graph.json` | Output graph JSON |
| `--nvd-api-key KEY` | `$NVD_API_KEY` env | NVD API key |
| `--cache-dir DIR` | `extractor/.nvd_cache` | NVD cache directory |

---

## 2. Analysis CLI — `post_extraction/main.py`

The analysis engine. Run from the `post_extraction/` directory. All commands accept `--input`/`-i` for a JSON file, and most accept `--output`/`-o` to save reports.

```bash
cd post_extraction
python main.py <command> [options]
```

> These commands are also invoked automatically by the root orchestrator's `visualize` and `report` steps.

---

### `full-report` — Kill-chain audit

Runs BFS, Dijkstra, DFS, RBAC, critical-node, and classification in one pass.

```bash
python main.py full-report --input ../cluster-graph.json
python main.py full-report --input ../cluster-graph.json --output report.txt
python main.py full-report --input ../cluster-graph.json --output-json report.json
python main.py full-report --input ../cluster-graph.json --blast-source "internet" --blast-depth 5
python main.py full-report --input ../cluster-graph.json --no-enrich     # Skip NVD lookup
python main.py full-report --input ../cluster-graph.json --no-cvss-weights
```

---

### `shortest-path` — Dijkstra attack path

Finds the single minimum-weight path between source and target.

```bash
python main.py shortest-path --input ../cluster-graph.json --source "internet" --target "prod-db"
python main.py shortest-path --input ../cluster-graph.json -s "web-frontend" -t "secret-db" -o path.txt
python main.py shortest-path --input ../cluster-graph.json -s "internet" -t "prod-db" --output-json path.json
```

| Flag | Description |
|------|-------------|
| `--source / -s` | Source node name or ID **(required)** |
| `--target / -t` | Target node name or ID **(required)** |
| `--input / -i` | Input JSON file **(required)** |
| `--output / -o` | Save text report |
| `--output-json` | Save JSON export |
| `--enrich/--no-enrich` | Live NVD CVE fetch |
| `--cvss-weights/--no-cvss-weights` | Use CVSS scores in edge weights |

---

### `blast-radius` — BFS reachability

Lists every node reachable from a source within a given hop depth.

```bash
python main.py blast-radius --input ../cluster-graph.json --source "internet" --depth 4
python main.py blast-radius --input ../cluster-graph.json -s "web-frontend" -d 3 -o radius.txt
python main.py blast-radius --input ../cluster-graph.json -s "internet" -d 5 --output-json blast.json
```

---

### `cycles` — DFS cycle detection

Detects privilege escalation loops in the attack graph.

```bash
python main.py cycles --input ../cluster-graph.json
python main.py cycles --input ../cluster-graph.json --output cycles.txt
python main.py cycles --input ../cluster-graph.json --output-json cycles.json
```

---

### `critical-node` — Chokepoint analysis

Identifies nodes whose removal most disrupts attack paths (graph surgery).

```bash
python main.py critical-node --input ../cluster-graph.json
python main.py critical-node --input ../cluster-graph.json --top 5
python main.py critical-node --input ../cluster-graph.json --top 10 --output critical.txt
```

---

### `rbac-audit` — RBAC risk scanner

Detects wildcard permissions, cluster-admin bindings, and escalation paths.

```bash
python main.py rbac-audit --input ../cluster-graph.json
python main.py rbac-audit --input ../cluster-graph.json --output rbac-audit.txt
python main.py rbac-audit --input ../cluster-graph.json --output-json rbac.json
```

---

### `node-risk` — Path centrality risk scoring

Computes amplified risk scores based on how many attack paths pass through each node.

```bash
python main.py node-risk --input ../cluster-graph.json
python main.py node-risk --input ../cluster-graph.json --top 10
python main.py node-risk --input ../cluster-graph.json --top 10 --output risk-map.txt
```

---

### `classify` — Attack path classification

Categorises paths as lateral movement, credential theft, privilege escalation, etc.

```bash
python main.py classify --input ../cluster-graph.json
python main.py classify --input ../cluster-graph.json --output classification.txt
```

---

### `explain` — Natural language path explanation

Generates a plain-English narrative for the attack path between two nodes.

```bash
python main.py explain --input ../cluster-graph.json --source "internet" --target "prod-db"
python main.py explain --input ../cluster-graph.json -s "web-frontend" -t "secret-db"
```

---

### `diff` — Compare two snapshots

Computes structural differences (new/removed nodes, edges, attack paths) between two graph JSON files.

```bash
python main.py diff baseline.json current.json
python main.py diff baseline.json current.json --output-json diff.json
python main.py diff baseline.json current.json --neo4j-uri bolt://localhost:7687
```

---

### `temporal-snapshot` — Capture a manual snapshot

```bash
python main.py temporal-snapshot --input ../cluster-graph.json
python main.py temporal-snapshot --input ../cluster-graph.json --no-diff   # Suppress diff output
python main.py temporal-snapshot --input ../cluster-graph.json --neo4j-uri bolt://localhost:7687
python main.py temporal-snapshot --input ../cluster-graph.json --persist-dir ./.my_snapshots
```

---

### `temporal-history` — View snapshot history

```bash
python main.py temporal-history
python main.py temporal-history --diff-all                  # Replay all consecutive diffs
python main.py temporal-history --diff-all --output-json history.json
python main.py temporal-history --persist-dir ./.my_snapshots
```

---

### `export-graph` — Save cluster graph to JSON

```bash
python main.py export-graph --input ../cluster-graph.json --output snapshot.json
python main.py export-graph --input ../cluster-graph.json --no-enrich   # Skip NVD
```

---

### `export-frontend` — Generate D3.js data

```bash
python main.py export-frontend --input ../cluster-graph.json
python main.py export-frontend --input ../cluster-graph.json --output visualizer/graph-data.json
```

Then serve:
```bash
cd visualizer
python -m http.server 8080
# Open http://localhost:8080
```

---

### `graph-info` — Graph structure summary

```bash
python main.py graph-info --input ../cluster-graph.json
```

Prints: total nodes, edges, sources, sinks, DAG status, node type breakdown, full node listing.

---

### `run-tests` — Built-in test suite

Runs 13 deterministic tests covering BFS, Dijkstra, DFS, critical-node, and risk scoring.

```bash
python main.py run-tests
```

---

## 3. Watcher — `watcher.py`

Can be called directly (bypassing the orchestrator):

```bash
python watcher.py                                               # Watch cluster-graph.json, 15s interval
python watcher.py --interval 30                                 # Poll every 30s
python watcher.py --graph ./path/to/cluster-graph.json          # Custom graph path
python watcher.py --no-neo4j                                    # Disable Neo4j
python watcher.py --neo4j-uri bolt://localhost:7687 \
                  --neo4j-user neo4j --neo4j-pass secret        # Connect to Neo4j
python watcher.py --persist-dir ./.my_snapshots                 # Custom snapshot store
python watcher.py --log-level DEBUG                             # Verbose logging
```

| Flag | Default | Description |
|------|---------|-------------|
| `--graph PATH` | `cluster-graph.json` | File to monitor |
| `--interval SECONDS` | `15` | Poll frequency |
| `--persist-dir DIR` | `.temporal_snapshots` | Snapshot persistence |
| `--neo4j-uri URI` | *(hardcoded cloud URI)* | Neo4j connection |
| `--neo4j-user USER` | `neo4j` | Neo4j username |
| `--neo4j-pass PASS` | *(see source)* | Neo4j password |
| `--no-neo4j` | `false` | Disable Neo4j even if URI is set |
| `--log-level LEVEL` | `INFO` | Logging verbosity |

**What the watcher exports to Neo4j on change:**
- `Snapshot` nodes (point-in-time)
- `DiffEvent` nodes (structural change records)
- `Alert` nodes (security alerts triggered by the change)
- `AttackPath` chains (new/removed paths as linked node chains)

---

## 4. Fetcher — `fetcher.py`

Can be called directly (bypassing the orchestrator):

```bash
python fetcher.py                                   # Collect + extract every 60s
python fetcher.py --interval 30                     # Every 30s
python fetcher.py --skip-collect                    # Only re-extract (no kubectl)
python fetcher.py --once                            # One cycle, then exit
python fetcher.py --nvd-api-key YOUR_KEY            # Add NVD key for CVE enrichment
python fetcher.py --input path/to/cluster.json \
                  --output path/to/cluster-graph.json   # Custom paths
```

| Flag | Default | Description |
|------|---------|-------------|
| `--interval SECONDS` | `60` | Fetch interval |
| `--resources-dir DIR` | `extractor/k8s_resources` | kubectl output directory |
| `--input PATH` | `extractor/k8s_resources/cluster.json` | cluster.json input for extraction |
| `--output PATH` | `cluster-graph.json` | Output graph JSON |
| `--nvd-api-key KEY` | `$NVD_API_KEY` env | NVD key for faster CVE lookups |
| `--cache-dir DIR` | `extractor/.nvd_cache` | NVD cache directory |
| `--skip-collect` | `false` | Skip `collect_all_resources.py` |
| `--once` | `false` | Single run (no loop) |

**Behaviour:**
- First cycle: verbose output showing each sub-step
- Subsequent cycles: compact single-line log per cycle
- Hash-based change detection to avoid unnecessary watcher triggers

---

## 5. extractor Scripts

These are invoked automatically by the orchestrator. You can also call them directly.

### `extractor/collect_all_resources.py` — kubectl collector

```bash
cd extractor
python collect_all_resources.py
python collect_all_resources.py --output ./my_resources
```

**Collects per-namespace:** `pods`, `services`, `deployments`, `roles`, `rolebindings`, `serviceaccounts`, `secrets`, `configmaps`, `networkpolicies`

**Collects cluster-wide:** `clusterroles`, `clusterrolebindings`, `nodes`

**Output:** `k8s_resources/cluster.json` (combined) + per-namespace JSON files.

---

### `extractor/extract_relationships.py` — graph builder

```bash
cd extractor
python extract_relationships.py
python extract_relationships.py --input k8s_resources/cluster.json --output ../cluster-graph.json
python extract_relationships.py --nvd-api-key YOUR_KEY
python extract_relationships.py --cache-dir ./.my_cache
```

| Flag | Default | Description |
|------|---------|-------------|
| `--input PATH` | `k8s_resources/cluster.json` | Input from collector |
| `--output PATH` | `../cluster-graph.json` | Output attack graph |
| `--nvd-api-key KEY` | *(none)* | NIST NVD API key |
| `--cache-dir DIR` | `.nvd_cache` | CVE cache (30-day TTL) |

**What it does:**
- Parses all K8s resources
- Filters out system namespaces (`kube-system`, etc.)
- Builds nodes for: Pods, Services, Deployments, ServiceAccounts, Secrets, ConfigMaps, Roles, ClusterRoles, Nodes, Namespaces
- Fetches CVE scores from NVD API (with caching)
- Computes risk scores per node type
- Extracts edges (relationships): `pod→service`, `pod→secret`, `sa→role`, `deployment→pod`, etc.
- Outputs `cluster-graph.json` in the canonical format consumed by the analysis engine

---

### `extractor/creating-cluster/apply-all.sh` — test cluster setup

```bash
cd extractor/creating-cluster
bash apply-all.sh
```

Applies all YAML manifests to create a multi-namespace test cluster with intentional security misconfigurations (for demo/testing purposes).

Manifests included:
- `namespace.yml` — namespaces
- `deployment.yml` — workloads
- `service.yml` — services
- `serviceAccount.yml` — service accounts
- `secrets.yml` — secrets with risk labels
- `configMap.yml` — configmaps with sensitivity labels
- `role.yml` / `rolebinding.yml` — RBAC with risky permissions
- `clusterRole.yml` / `clusterRolebinding.yml` — cluster-wide RBAC
- `cluster.yml` — cluster config

---

## 6. Global Flags Reference

### Intelligence flags (Analysis CLI)

| Flag | Description |
|------|-------------|
| `--enrich` / `--no-enrich` | Fetch live CVSS scores from NIST NVD. Default: disabled for `--input` mode |
| `--cvss-weights` / `--no-cvss-weights` | Use CVSS scores to weight edges (favours high-severity paths in Dijkstra) |

### Output flags (Analysis CLI)

| Flag | Description |
|------|-------------|
| `--output / -o PATH` | Save human-readable text report |
| `--output-json PATH` | Save machine-readable JSON export |

### Risk model

All nodes store two components separately for transparent reasoning:

```
Risk Score = (Likelihood / 10.0) × Impact
```

Likelihood and impact are computed per resource type:
- **Secrets**: up to 10.0 for `crown-jewel: true` or high-sensitivity token/credential names
- **ClusterRoles**: 10.0 for wildcard permissions (`*`)
- **Services**: 7.5 for `LoadBalancer`, 6.5 for `NodePort`
- **Pods**: based on max CVSS score of associated CVEs

---

## Quick Workflow Cheatsheet

```bash
# ★ Everything in one command
python main.py run

# One-shot pipeline
python main.py pipeline

# Skip kubectl (reuse cached cluster.json)
python main.py pipeline --skip-collect

# Analysis only (from existing graph)
cd post_extraction && python main.py full-report --input ../cluster-graph.json

# Specific attack path
cd post_extraction && python main.py shortest-path --input ../cluster-graph.json -s internet -t prod-db

# Start continuous monitoring
python main.py fetch --interval 30 &   # Refreshes graph
python main.py watch --no-neo4j &      # Diffs on change
cd post_extraction/visualizer && python -m http.server 8080  # Serve dashboard

# Run tests
cd post_extraction && python main.py run-tests
```
