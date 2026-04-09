# Test Case Answers — Algorithm Verification Reference

> **Purpose**: Hand-computed correct answers for cross-checking algorithm outputs.
> **Weight formula**: `effective_cost = base_weight × (1 − cvss/10)` when CVSS is present; minimum 0.1. When CVSS is null, `effective_cost = base_weight`.

---

## Test Case 1: Linear Chain (`test-case-1-linear-chain.json`)

### Graph Structure
```
A ──[reaches, w=3.0, CVE, CVSS=7.5]──▸ B ──[uses, w=2.0]──▸ C ──[bound-to, w=4.0]──▸ D ──[can-read, w=5.0]──▸ E
```

### Effective Edge Weights (with CVSS reduction)
| Edge | Base Weight | CVSS | Effective Weight |
|------|------------|------|-----------------|
| A→B  | 3.0        | 7.5  | 3.0 × (1 − 0.75) = **0.75** |
| B→C  | 2.0        | null | **2.0** |
| C→D  | 4.0        | null | **4.0** |
| D→E  | 5.0        | null | **5.0** |

### Dijkstra: Shortest Path A → E
- **Path**: `A → B → C → D → E`
- **Total Risk**: 0.75 + 2.0 + 4.0 + 5.0 = **11.75**
- **Hop Count**: 4
- **Severity**: 11.75 > 10 → **HIGH**

### BFS: Blast Radius from A (max_depth=3)
| Hop | Nodes |
|-----|-------|
| 1   | B     |
| 2   | C     |
| 3   | D     |
- **Total Affected**: 3 (E is at depth 4, beyond max_depth=3)

### BFS: Blast Radius from A (max_depth=4)
| Hop | Nodes |
|-----|-------|
| 1   | B     |
| 2   | C     |
| 3   | D     |
| 4   | E     |
- **Total Affected**: 4

### DFS: Cycle Detection
- **Cycles Found**: 0
- **Is DAG**: Yes

### all_shortest_paths (sources→sinks)
- Sources: `[A]`, Sinks: `[E]`
- **Path 1**: A → B → C → D → E (risk: 11.75)
- **Total paths**: 1

---

## Test Case 2: Diamond (`test-case-2-diamond.json`)

### Graph Structure
```
A ──[w=1.0]──▸ B ──[w=2.0]──▸ D
A ──[w=5.0]──▸ C ──[w=1.0]──▸ D
```

### Effective Edge Weights (no CVSS on any edge)
| Edge | Effective Weight |
|------|-----------------|
| A→B  | 1.0 |
| B→D  | 2.0 |
| A→C  | 5.0 |
| C→D  | 1.0 |

### Dijkstra: Shortest Path A → D
- **Path**: `A → B → D` (cost = 1.0 + 2.0 = **3.0**)
- NOT A → C → D (cost = 5.0 + 1.0 = 6.0)
- **Hop Count**: 2
- **Severity**: 3.0 ≤ 5 → **LOW**

### BFS: Blast Radius from A (max_depth=2)
| Hop | Nodes |
|-----|-------|
| 1   | B, C  |
| 2   | D     |
- **Total Affected**: 3
- Note: B and C are at the same depth (order may vary)

### BFS: Blast Radius from A (max_depth=1)
| Hop | Nodes |
|-----|-------|
| 1   | B, C  |
- **Total Affected**: 2

### DFS: Cycle Detection
- **Cycles Found**: 0
- **Is DAG**: Yes

### all_shortest_paths (sources→sinks)
- Sources: `[A]`, Sinks: `[D]`
- **Path 1**: A → B → D (risk: 3.0)
- **Total paths**: 1

---

## Test Case 3: Cycle (`test-case-3-cycle.json`)

### Graph Structure
```
A ──[w=3.0]──▸ B ──[w=2.0]──▸ C ──[w=4.0]──▸ D ──[w=5.0]──▸ E
                ↑                              |
                └───────[w=1.0]────────────────┘
              B ──[w=20.0]──▸ E (direct shortcut)
```

### Effective Edge Weights (no CVSS)
| Edge | Effective Weight |
|------|-----------------|
| A→B  | 3.0 |
| B→C  | 2.0 |
| C→D  | 4.0 |
| D→B  | 1.0 |
| D→E  | 5.0 |
| B→E  | 20.0 |

### Dijkstra: Shortest Path A → E
- **Path A → B → C → D → E**: 3.0 + 2.0 + 4.0 + 5.0 = **14.0**
- Path A → B → E: 3.0 + 20.0 = 23.0
- **Winner**: `A → B → C → D → E` (cost = **14.0**)
- **Hop Count**: 4
- **Severity**: 14.0 > 10 → **HIGH**

### BFS: Blast Radius from A (max_depth=3)
| Hop | Nodes |
|-----|-------|
| 1   | B     |
| 2   | C, E  |
| 3   | D     |
- **Total Affected**: 4
- Note: At hop 2, both C (via B→C) and E (via B→E) are discovered. D→B is not traversed because B is already visited. D is discovered at hop 3 (via C→D).

### DFS: Cycle Detection
- **Cycle 1**: `B → C → D → B` (3 nodes)
  - Cycle risk: 2.0 + 4.0 + 1.0 = **7.0**
- **Total Cycles**: 1

### all_shortest_paths (sources→sinks)
- Sources: `[A]`, Sinks: `[E]`
- **Path 1**: A → B → C → D → E (risk: 14.0)
- **Total paths**: 1

---

## Test Case 4: Disconnected (`test-case-4-disconnected.json`)

### Graph Structure
```
Component 1: A ──[w=3.0]──▸ B ──[w=4.0]──▸ C
Component 2: D ──[w=2.0]──▸ E ──[w=5.0]──▸ F
```

### Effective Edge Weights (no CVSS)
| Edge | Effective Weight |
|------|-----------------|
| A→B  | 3.0 |
| B→C  | 4.0 |
| D→E  | 2.0 |
| E→F  | 5.0 |

### Dijkstra: Shortest Path A → F
- **Result**: `None` (no path — different components)

### Dijkstra: Shortest Path D → F
- **Path**: `D → E → F` (cost = 2.0 + 5.0 = **7.0**)
- **Hop Count**: 2
- **Severity**: 7.0 > 5 → **MEDIUM**

### BFS: Blast Radius from A (max_depth=3)
| Hop | Nodes |
|-----|-------|
| 1   | B     |
| 2   | C     |
- **Total Affected**: 2 (cannot reach D, E, F)

### BFS: Blast Radius from D (max_depth=3)
| Hop | Nodes |
|-----|-------|
| 1   | E     |
| 2   | F     |
- **Total Affected**: 2

### DFS: Cycle Detection
- **Cycles Found**: 0
- **Is DAG**: Yes

### all_shortest_paths (sources→sinks)
- Sources: `[A, D]`, Sinks: `[F]`
- A → F: None (unreachable)
- D → E → F: risk = 7.0
- **Paths found**: 1
- **Path 1**: D → E → F (risk: 7.0)

---

## Test Case 5: CVSS Weight Reduction (`test-case-5-cvss-weights.json`)

### Graph Structure
```
A ──[w=8.0, CVSS=9.0]──▸ B ──[w=8.0, CVSS=9.0]──▸ D
A ──[w=4.0, no CVSS]────▸ C ──[w=4.0, no CVSS]────▸ D
```

### Effective Edge Weights
| Edge | Base Weight | CVSS | Effective Weight |
|------|------------|------|-----------------|
| A→B  | 8.0        | 9.0  | 8.0 × (1 − 0.9) = 8.0 × 0.1 = **0.8** |
| B→D  | 8.0        | 9.0  | 8.0 × (1 − 0.9) = 8.0 × 0.1 = **0.8** |
| A→C  | 4.0        | null | **4.0** |
| C→D  | 4.0        | null | **4.0** |

### Dijkstra: Shortest Path A → D (with CVSS weighting)
- Path A → B → D: 0.8 + 0.8 = **1.6**
- Path A → C → D: 4.0 + 4.0 = 8.0
- **Winner**: `A → B → D` (cost = **1.6**)
- **Hop Count**: 2
- **Severity**: 1.6 ≤ 5 → **LOW**

> **Key insight**: Despite the base weights being higher on the CVE-affected path (8+8=16 vs 4+4=8), the CVSS 9.0 score reduces each edge to 10% of its base cost, making the vulnerable path the "easiest" attack vector — which is the correct real-world interpretation.

### BFS: Blast Radius from A (max_depth=2)
| Hop | Nodes |
|-----|-------|
| 1   | B, C  |
| 2   | D     |
- **Total Affected**: 3

### DFS: Cycle Detection
- **Cycles Found**: 0
- **Is DAG**: Yes

### all_shortest_paths (sources→sinks)
- Sources: `[A]`, Sinks: `[D]`
- **Path 1**: A → B → D (risk: 1.6)
- **Total paths**: 1

---

## Test Case 6: Multiple Sources & Sinks (`test-case-6-multi-source-sink.json`)

### Graph Structure
```
S1 ──[w=2.0]──▸ M1 ──[w=2.0]──▸ M2 ──[w=4.0]──▸ M3 ──[w=3.0]──▸ T1
                 │               │                  └──[w=5.0]──▸ T2
                 │               └──[w=6.0]──▸ T1
                 └──[w=10.0]──▸ T1

S2 ──[w=3.0]──▸ M2
```

### Effective Edge Weights (no CVSS)
| Edge   | Effective Weight |
|--------|-----------------|
| S1→M1  | 2.0  |
| S2→M2  | 3.0  |
| M1→M2  | 2.0  |
| M2→M3  | 4.0  |
| M2→T1  | 6.0  |
| M3→T1  | 3.0  |
| M3→T2  | 5.0  |
| M1→T1  | 10.0 |

### Dijkstra: All source→sink paths

**S1 → T1** (multiple routes):
- S1→M1→T1: 2.0 + 10.0 = 12.0
- S1→M1→M2→T1: 2.0 + 2.0 + 6.0 = 10.0
- S1→M1→M2→M3→T1: 2.0 + 2.0 + 4.0 + 3.0 = 11.0
- **Shortest**: `S1 → M1 → M2 → T1` (risk = **10.0**)
- Severity: 10.0 > 5 → **MEDIUM** (not > 10, so MEDIUM)

**S1 → T2**:
- S1→M1→M2→M3→T2: 2.0 + 2.0 + 4.0 + 5.0 = 13.0
- **Shortest**: `S1 → M1 → M2 → M3 → T2` (risk = **13.0**)
- Severity: 13.0 > 10 → **HIGH**

**S2 → T1** (multiple routes):
- S2→M2→T1: 3.0 + 6.0 = 9.0
- S2→M2→M3→T1: 3.0 + 4.0 + 3.0 = 10.0
- **Shortest**: `S2 → M2 → T1` (risk = **9.0**)
- Severity: 9.0 > 5 → **MEDIUM**

**S2 → T2**:
- S2→M2→M3→T2: 3.0 + 4.0 + 5.0 = 12.0
- **Shortest**: `S2 → M2 → M3 → T2` (risk = **12.0**)
- Severity: 12.0 > 10 → **HIGH**

### all_shortest_paths (sorted by risk ascending)
| # | Path | Risk | Severity |
|---|------|------|----------|
| 1 | S2 → M2 → T1 | 9.0 | MEDIUM |
| 2 | S1 → M1 → M2 → T1 | 10.0 | MEDIUM |
| 3 | S2 → M2 → M3 → T2 | 12.0 | HIGH |
| 4 | S1 → M1 → M2 → M3 → T2 | 13.0 | HIGH |

### BFS: Blast Radius from S1 (max_depth=3)
| Hop | Nodes |
|-----|-------|
| 1   | M1    |
| 2   | M2, T1 |
| 3   | M3    |
- **Total Affected**: 4
- Note: T1 is reached at hop 2 via M1→T1, and M2 also at hop 2 via M1→M2. M2→T1 won't re-add T1. M3 at hop 3 via M2→M3. T2 is at hop 4 (beyond max_depth).

### BFS: Blast Radius from S2 (max_depth=3)
| Hop | Nodes |
|-----|-------|
| 1   | M2    |
| 2   | M3, T1 |
| 3   | T2    |
- **Total Affected**: 4

### DFS: Cycle Detection
- **Cycles Found**: 0
- **Is DAG**: Yes

---

## Test Case 7: Multiple Overlapping Cycles (`test-case-7-multi-cycle.json`)

### Graph Structure
```
A ──[w=2.0]──▸ B ──[w=3.0]──▸ C ──[w=4.0]──▸ D ──[w=2.0]──▸ E ──[w=5.0]──▸ F
               ↑              |                               |
               └──[w=3.0]─────┘                               |
                              ↑                                |
                              └────────[w=1.0]─────────────────┘
                                       D ──[w=6.0]──▸ F
```

### Effective Edge Weights (no CVSS)
| Edge | Effective Weight |
|------|-----------------|
| A→B  | 2.0 |
| B→C  | 3.0 |
| C→B  | 3.0 |
| C→D  | 4.0 |
| D→E  | 2.0 |
| E→C  | 1.0 |
| E→F  | 5.0 |
| D→F  | 6.0 |

### DFS: Cycle Detection
Using Johnson's algorithm (nx.simple_cycles), the unique cycles are:

- **Cycle 1**: `B → C → B` (or canonical: `B, C`)
  - Cycle risk: 3.0 + 3.0 = **6.0**
- **Cycle 2**: `C → D → E → C` (or canonical: `C, D, E`)
  - Cycle risk: 4.0 + 2.0 + 1.0 = **7.0**
- **Cycle 3**: `B → C → D → E → C → B` — This is NOT a simple cycle because C is visited twice. However, Johnson's finds elementary circuits, so this would be: `B → C → D → E → C` is not elementary since C repeats.
  
  Actually, let's reconsider. The edges are: B→C, C→D, D→E, E→C, C→B.
  - Elementary cycle through B: B → C → D → E → C → B — this visits C twice, NOT elementary.
  - So the only elementary cycles are:
    - **{B, C}**: B→C→B  
    - **{C, D, E}**: C→D→E→C

- **Total Unique Cycles**: 2

### Dijkstra: Shortest Path A → F
- A→B→C→D→F: 2.0 + 3.0 + 4.0 + 6.0 = 15.0
- A→B→C→D→E→F: 2.0 + 3.0 + 4.0 + 2.0 + 5.0 = 16.0
- **Shortest**: `A → B → C → D → F` (cost = **15.0**)
- **Hop Count**: 4
- **Severity**: 15.0 > 10 → **HIGH**

### BFS: Blast Radius from A (max_depth=3)
| Hop | Nodes |
|-----|-------|
| 1   | B     |
| 2   | C     |
| 3   | D     |
- **Total Affected**: 3
- Note: E and F are at depth 4+, beyond max_depth=3. C→B won't re-add B.

### BFS: Blast Radius from A (max_depth=5)
| Hop | Nodes |
|-----|-------|
| 1   | B     |
| 2   | C     |
| 3   | D     |
| 4   | E, F  |
- **Total Affected**: 5
- Note: E→C won't re-add C (already visited). E→F adds F at hop 5? Actually E is at hop 4, so F via E→F would be at hop 5. D→F adds F at hop 4 (via D). So F is at hop 4 via D→F. E is at hop 4 via D→E. E→F would be hop 5 but F is already visited.
- Corrected: at hop 4, both E (via D→E) and F (via D→F) are discovered.

### all_shortest_paths (sources→sinks)
- Sources: `[A]`, Sinks: `[F]`
- **Path 1**: A → B → C → D → F (risk: 15.0)
- **Total paths**: 1

---

## Test Case 8: Deep BFS (`test-case-8-deep-bfs.json`)

### Graph Structure
```
A ──[w=2.0]──▸ B ──[w=3.0]──▸ C ──[w=2.0]──▸ D ──[w=3.0]──▸ E ──[w=4.0]──▸ F ──[w=5.0]──▸ G ──[w=6.0]──▸ H
                └──[w=4.0]──▸ D
                    C ──[w=10.0]──▸ E
```

### Effective Edge Weights (no CVSS)
| Edge | Effective Weight |
|------|-----------------|
| A→B  | 2.0  |
| B→C  | 3.0  |
| B→D  | 4.0  |
| C→D  | 2.0  |
| D→E  | 3.0  |
| E→F  | 4.0  |
| F→G  | 5.0  |
| G→H  | 6.0  |
| C→E  | 10.0 |

### BFS: Blast Radius from A (max_depth=3)
- **Hop 0**: A (source, not counted)
- **Hop 1**: B (via A→B)
- **Hop 2**: C (via B→C), D (via B→D)
- **Hop 3**: E (via C→D→E? No — D is at hop 2, so D→E would be hop 3. Also C→E at hop 3, and C→D but D is already visited)
  - From C (hop 2): C→D (D already at hop 2), C→E (E at hop 3)
  - From D (hop 2): D→E (E at hop 3, but might already be queued)
  - BFS processes in order: B is dequeued → adds C and D. Then C is dequeued → D already visited, adds E. Then D is dequeued → E already visited. So E is added once at hop 3.

| Hop | Nodes |
|-----|-------|
| 1   | B     |
| 2   | C, D  |
| 3   | E     |
- **Total Affected**: 4

### BFS: Blast Radius from A (max_depth=5)
| Hop | Nodes |
|-----|-------|
| 1   | B     |
| 2   | C, D  |
| 3   | E     |
| 4   | F     |
| 5   | G     |
- **Total Affected**: 6 (H is at hop 6, beyond max_depth=5)

### BFS: Blast Radius from A (max_depth=7)
| Hop | Nodes |
|-----|-------|
| 1   | B     |
| 2   | C, D  |
| 3   | E     |
| 4   | F     |
| 5   | G     |
| 6   | H     |
- **Total Affected**: 7

### Dijkstra: Shortest Path A → H
- Via A→B→C→D→E→F→G→H: 2.0 + 3.0 + 2.0 + 3.0 + 4.0 + 5.0 + 6.0 = **25.0**
- Via A→B→D→E→F→G→H: 2.0 + 4.0 + 3.0 + 4.0 + 5.0 + 6.0 = **24.0**
- Via A→B→C→E→F→G→H: 2.0 + 3.0 + 10.0 + 4.0 + 5.0 + 6.0 = **30.0**
- **Shortest**: `A → B → D → E → F → G → H` (cost = **24.0**)
- **Hop Count**: 6
- **Severity**: 24.0 > 20 → **CRITICAL**

### DFS: Cycle Detection
- **Cycles Found**: 0
- **Is DAG**: Yes

### all_shortest_paths (sources→sinks)
- Sources: `[A]`, Sinks: `[H]`
- **Path 1**: A → B → D → E → F → G → H (risk: 24.0)
- **Total paths**: 1

---

## Test Case 9: Single Node (`test-case-9-single-node.json`)

### Graph Structure
```
X (sole node, is_source=true, is_sink=true)
```

### Dijkstra: Shortest Path X → X
- Source equals target. NetworkX `dijkstra_path(G, X, X)` returns `[X]` with length 0.
- **Path**: `[X]`
- **Total Risk**: 0.0
- **Hop Count**: 0
- **Severity**: 0.0 ≤ 5 → **LOW**

### BFS: Blast Radius from X (max_depth=3)
- No successors.
- **Layers**: empty
- **Total Affected**: 0

### DFS: Cycle Detection
- No edges → **0 cycles**
- **Is DAG**: Yes

### all_shortest_paths (sources→sinks)
- Sources: `[X]`, Sinks: `[X]`
- Dijkstra X→X returns path `[X]` with risk 0.0
- **Total paths**: 1 (X is both source and sink)
- **Path 1**: X (risk: 0.0)

---

## Test Case 10: Self-Loop (`test-case-10-self-loop.json`)

### Graph Structure
```
A ──[w=3.0]──▸ B ──[w=5.0]──▸ C
               ↻ [w=1.0, self-escalate]
A ──[w=20.0]──▸ C
```

### Effective Edge Weights (no CVSS)
| Edge | Effective Weight |
|------|-----------------|
| A→B  | 3.0  |
| B→B  | 1.0  |
| B→C  | 5.0  |
| A→C  | 20.0 |

### Dijkstra: Shortest Path A → C
- Path A→B→C: 3.0 + 5.0 = **8.0**
- Path A→C: 20.0
- (Dijkstra will not loop through B→B since B is already settled)
- **Shortest**: `A → B → C` (cost = **8.0**)
- **Hop Count**: 2
- **Severity**: 8.0 > 5 → **MEDIUM**

### BFS: Blast Radius from A (max_depth=3)
| Hop | Nodes |
|-----|-------|
| 1   | B, C  |
| 2   | (none new — B→B self-loop doesn't add, B→C but C already visited) |
- **Total Affected**: 2
- Note: B and C are both at hop 1 (A→B and A→C). B→B self-loop: B already visited. B→C: C already visited. No new nodes at depth 2+.

### DFS: Cycle Detection
- **Cycle 1**: `B → B` (self-loop, 1 node)
  - Cycle risk: 1.0
- **Total Unique Cycles**: 1

### all_shortest_paths (sources→sinks)
- Sources: `[A]`, Sinks: `[C]`
- **Path 1**: A → B → C (risk: 8.0)
- **Total paths**: 1

---

## Summary Table

| Test Case | Dijkstra Path | Dijkstra Cost | BFS Affected (depth=3) | DFS Cycles |
|-----------|---------------|---------------|------------------------|------------|
| 1. Linear Chain | A→B→C→D→E | 11.75 | 3 | 0 |
| 2. Diamond | A→B→D | 3.0 | 3 | 0 |
| 3. Cycle | A→B→C→D→E | 14.0 | 4 | 1 ({B,C,D}) |
| 4. Disconnected | A→F: None; D→E→F: 7.0 | — | 2 (from A) | 0 |
| 5. CVSS Weights | A→B→D | 1.6 | 3 | 0 |
| 6. Multi Source/Sink | varies | 9.0–13.0 | 4 (from S1) | 0 |
| 7. Multi Cycle | A→B→C→D→F | 15.0 | 3 | 2 |
| 8. Deep BFS | A→B→D→E→F→G→H | 24.0 | 4 | 0 |
| 9. Single Node | [X] | 0.0 | 0 | 0 |
| 10. Self-Loop | A→B→C | 8.0 | 2 | 1 ({B}) |
