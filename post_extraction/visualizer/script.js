/**
 * KubeAttackViz v3.0 — D3.js Attack Graph Visualization
 *
 * Features:
 *   - Auto-load graph data (no manual upload)
 *   - Polling for live updates with content-hash dedup
 *   - Snapshot timeline with interactive navigation
 *   - Color-coded nodes by resource type
 *   - Animated attack path & cycle edges
 *   - Critical node highlighting
 *   - Hover tooltips, click-to-highlight, detail panel
 *   - Animated stat counters
 */

// ─── Constants ──────────────────────────────────────────────────────────────

const NODE_COLORS = {
    pod:                  '#60a5fa',
    service:              '#34d399',
    serviceaccount:       '#f97316',
    role:                 '#a78bfa',
    clusterrole:          '#8b5cf6',
    rolebinding:          '#fbbf24',
    clusterrolebinding:   '#f59e0b',
    secret:               '#f43f5e',
    configmap:            '#2dd4bf',
    database:             '#475569',
    node:                 '#64748b',
    namespace:            '#818cf8',
    deployment:           '#38bdf8',
    ingress:              '#22d3ee',
};

const DEFAULT_NODE_COLOR  = '#94a3b8';
const ATTACK_PATH_COLOR   = '#f43f5e';
const CYCLE_EDGE_COLOR    = '#f59e0b';
const CRITICAL_NODE_COLOR = '#fbbf24';

const BASE_RADIUS     = 7;
const SOURCE_RADIUS   = 11;
const SINK_RADIUS     = 10;
const CRITICAL_RADIUS = 15;

const POLL_INTERVAL_MS = 5000;

// ─── State ──────────────────────────────────────────────────────────────────

let graphData       = null;
let simulation      = null;
let svg             = null;
let gMain           = null;
let linkGroup       = null;
let nodeGroup       = null;
let labelGroup      = null;
let activePathIdx   = null;
let selectedNode    = null;
let zoom            = null;
let lastDataHash    = null;
let pollTimer       = null;
let isSnapshotView  = false;
let snapshotData    = [];

// Sets for efficient lookup
let attackPathEdges  = new Set();
let cycleEdges       = new Set();
let criticalNodeIds  = new Set();

// ─── Init ───────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    initSVG();
    initControls();
    autoLoadData();
    loadTimeline();
});

function initSVG() {
    svg = d3.select('#graph-svg');

    zoom = d3.zoom()
        .scaleExtent([0.1, 6])
        .wheelDelta(event => {
            return -event.deltaY * (event.deltaMode === 1 ? 0.05 : event.deltaMode === 2 ? 1 : 0.001) * (event.ctrlKey ? 10 : 1);
        })
        .on('zoom', (event) => {
            gMain.attr('transform', event.transform);
        });

    svg.call(zoom);
    gMain = svg.append('g').attr('class', 'main-group');

    const defs = svg.append('defs');

    // Arrow markers
    const markers = [
        { id: 'arrowhead',        cls: 'arrowhead' },
        { id: 'arrowhead-attack', cls: 'arrowhead attack-path-arrow' },
        { id: 'arrowhead-cycle',  cls: 'arrowhead cycle-arrow' },
    ];
    for (const m of markers) {
        defs.append('marker')
            .attr('id', m.id)
            .attr('viewBox', '0 -5 10 10')
            .attr('refX', 20).attr('refY', 0)
            .attr('markerWidth', 7).attr('markerHeight', 7)
            .attr('orient', 'auto')
            .append('path')
            .attr('d', 'M0,-5L10,0L0,5')
            .attr('class', m.cls);
    }

    // Glow filter
    const glow = defs.append('filter')
        .attr('id', 'glow')
        .attr('x', '-50%').attr('y', '-50%')
        .attr('width', '200%').attr('height', '200%');
    glow.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'coloredBlur');
    const merge = glow.append('feMerge');
    merge.append('feMergeNode').attr('in', 'coloredBlur');
    merge.append('feMergeNode').attr('in', 'SourceGraphic');

    linkGroup  = gMain.append('g').attr('class', 'links');
    nodeGroup  = gMain.append('g').attr('class', 'nodes');
    labelGroup = gMain.append('g').attr('class', 'labels');
}

function initControls() {
    // Toggles
    document.getElementById('toggle-paths').addEventListener('change', updateVisibility);
    document.getElementById('toggle-cycles').addEventListener('change', updateVisibility);
    document.getElementById('toggle-labels').addEventListener('change', updateVisibility);
    document.getElementById('toggle-critical').addEventListener('change', updateVisibility);

    // Close detail panel
    document.getElementById('btn-close-detail').addEventListener('click', () => {
        document.getElementById('detail-panel').classList.add('hidden');
        clearHighlight();
    });

    // Zoom buttons
    document.getElementById('btn-zoom-in').addEventListener('click', zoomIn);
    document.getElementById('btn-zoom-out').addEventListener('click', zoomOut);
    document.getElementById('btn-zoom-reset').addEventListener('click', resetZoom);

    // Timeline drag-scroll
    const tc = document.getElementById('timeline-container');
    let isDragging = false, startX, scrollLeft;
    tc.addEventListener('mousedown', (e) => {
        isDragging = true;
        startX = e.pageX - tc.offsetLeft;
        scrollLeft = tc.scrollLeft;
    });
    tc.addEventListener('mouseleave', () => isDragging = false);
    tc.addEventListener('mouseup', () => isDragging = false);
    tc.addEventListener('mousemove', (e) => {
        if (!isDragging) return;
        e.preventDefault();
        const x = e.pageX - tc.offsetLeft;
        tc.scrollLeft = scrollLeft - (x - startX);
    });

    // Timeline wheel scroll
    tc.addEventListener('wheel', (e) => {
        e.preventDefault();
        tc.scrollLeft += e.deltaY;
    }, { passive: false });
}

// ─── Auto-load & Polling ────────────────────────────────────────────────────

async function autoLoadData() {
    setStatus('loading', 'Loading…');
    showLoading(true);

    try {
        const resp = await fetch('graph-data.json');
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const text = await resp.text();
        const hash = simpleHash(text);

        if (hash !== lastDataHash) {
            lastDataHash = hash;
            const data = JSON.parse(text);
            isSnapshotView = false;
            updateWatermark('Live View');
            loadGraphData(data);
            setStatus('connected', 'Live');
        }
    } catch (err) {
        console.warn('Auto-load failed:', err.message);
        setStatus('error', 'No data');
    }

    showLoading(false);
}

// Polling removed per user request to prevent file lock and race condition.
// Ensure live updates are fetched by refreshing the page.
function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const chr = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + chr;
        hash |= 0;
    }
    return hash.toString(36);
}

// ─── Status ─────────────────────────────────────────────────────────────────

function setStatus(state, text) {
    const dot = document.getElementById('status-dot');
    const label = document.getElementById('status-text');
    dot.className = 'status-dot ' + state;
    label.textContent = text;
}

function showLoading(show) {
    const overlay = document.getElementById('loading-overlay');
    if (show) {
        overlay.classList.remove('hidden');
    } else {
        overlay.classList.add('hidden');
    }
}

function updateWatermark(text) {
    const wm = document.getElementById('graph-watermark');
    document.getElementById('watermark-text').textContent = text;
    if (isSnapshotView) {
        wm.classList.add('snapshot-view');
    } else {
        wm.classList.remove('snapshot-view');
    }
}

// ─── Timeline ───────────────────────────────────────────────────────────────

async function loadTimeline() {
    try {
        const resp = await fetch('/api/snapshots');
        if (!resp.ok) return;
        const data = await resp.json();
        snapshotData = data.snapshots || [];
        renderTimeline(snapshotData);
        document.getElementById('snapshot-count-badge').textContent = snapshotData.length;
    } catch (err) {
        console.warn('Timeline load failed:', err.message);
    }
}

function renderTimeline(snapshots) {
    const track = document.getElementById('timeline-track');
    track.innerHTML = '';

    if (snapshots.length === 0) {
        track.innerHTML = '<div style="padding:8px;font-size:0.7rem;color:var(--text-faint);text-align:center;width:100%;">No snapshots yet</div>';
        return;
    }

    snapshots.forEach((snap, idx) => {
        const marker = document.createElement('div');
        marker.className = 'timeline-marker';
        if (idx === snapshots.length - 1) marker.classList.add('latest');

        const date = new Date(snap.timestamp);
        const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const dateStr = date.toLocaleDateString([], { month: 'short', day: 'numeric' });

        let changesHtml = '';
        if (snap.changes && snap.changes.length > 0) {
            changesHtml = '<div style="margin-top:4px; border-top:1px solid rgba(255,255,255,0.1); padding-top:4px;">';
            snap.changes.forEach(ch => {
                const color = ch.startsWith('+') ? 'var(--accent-green)' : (ch.startsWith('-') ? 'var(--accent-red)' : 'var(--text-primary)');
                changesHtml += `<div style="font-size:0.6rem; color:${color}; font-family:'JetBrains Mono', monospace; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${ch}">${ch}</div>`;
            });
            changesHtml += '</div>';
        }

        const tooltipContent = `
            <div class="timeline-tooltip-row">
                <span class="timeline-tooltip-key">ID</span>
                <span class="timeline-tooltip-val">${snap.snapshot_id.slice(0, 10)}…</span>
            </div>
            <div class="timeline-tooltip-row">
                <span class="timeline-tooltip-key">Time</span>
                <span class="timeline-tooltip-val">${dateStr} ${timeStr}</span>
            </div>
            ${snap.node_count !== undefined ? `
            <div class="timeline-tooltip-row">
                <span class="timeline-tooltip-key">Nodes/Edges</span>
                <span class="timeline-tooltip-val">${snap.node_count} / ${snap.edge_count}</span>
            </div>` : ''}
            ${changesHtml}
        `;

        marker.innerHTML = `
            <div class="timeline-marker-dot"></div>
            <div class="timeline-marker-time">${timeStr}</div>
            <div class="timeline-marker-meta">${dateStr}</div>
        `;

        marker.addEventListener('mouseenter', () => {
            const globalTooltip = document.getElementById('global-timeline-tooltip');
            globalTooltip.innerHTML = tooltipContent;
            globalTooltip.classList.remove('hidden');
            globalTooltip.style.opacity = '1';
            const rect = marker.getBoundingClientRect();
            globalTooltip.style.left = rect.left + (rect.width / 2) + 'px';
            globalTooltip.style.top = (rect.top - globalTooltip.offsetHeight - 8) + 'px';
        });

        marker.addEventListener('mouseleave', () => {
            const globalTooltip = document.getElementById('global-timeline-tooltip');
            globalTooltip.classList.add('hidden');
            globalTooltip.style.opacity = '0';
        });

        marker.addEventListener('click', () => loadSnapshot(snap.snapshot_id, marker));
        track.appendChild(marker);
    });

    // Scroll to latest
    const container = document.getElementById('timeline-container');
    requestAnimationFrame(() => {
        container.scrollLeft = container.scrollWidth;
    });
}

async function loadSnapshot(snapshotId, markerEl) {
    // Toggle off if clicking active snapshot — go back to live
    const wasActive = markerEl.classList.contains('active');
    document.querySelectorAll('.timeline-marker').forEach(m => m.classList.remove('active'));

    if (wasActive) {
        isSnapshotView = false;
        updateWatermark('Live View');
        lastDataHash = null; // Force reload on next poll
        autoLoadData();
        return;
    }

    markerEl.classList.add('active');
    setStatus('loading', 'Loading…');
    showLoading(true);

    try {
        const resp = await fetch(`/api/snapshots/${snapshotId}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();

        isSnapshotView = true;
        const date = new Date(data.timestamp);
        updateWatermark(`Snapshot · ${date.toLocaleTimeString()} ${date.toLocaleDateString([], { month: 'short', day: 'numeric' })}`);
        loadGraphData(data);
        setStatus('connected', 'Snapshot');
    } catch (err) {
        console.error('Snapshot load failed:', err);
        setStatus('error', 'Failed');
    }

    showLoading(false);
}

// ─── Data Loading ───────────────────────────────────────────────────────────

function loadGraphData(data) {
    // Normalize data (snapshots may have capitalized node types)
    if (data.nodes) {
        data.nodes.forEach(n => {
            if (n.type) n.type = n.type.toLowerCase();
        });
    }

    graphData = data;

    // Animated stat counters
    animateCounter('node-count', (data.nodes || []).length);
    animateCounter('edge-count', (data.edges || []).length);
    animateCounter('path-count', (data.attack_paths || []).length);
    animateCounter('cycle-count', (data.cycles || []).length);

    buildLookups(data);
    renderPathCards(data.attack_paths || []);
    renderGraph(data);
}

function animateCounter(elementId, targetValue) {
    const el = document.getElementById(elementId);
    const current = parseInt(el.textContent) || 0;
    if (current === targetValue) return;

    const duration = 400;
    const start = performance.now();

    function step(timestamp) {
        const progress = Math.min((timestamp - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        const value = Math.round(current + (targetValue - current) * eased);
        el.textContent = value;
        if (progress < 1) requestAnimationFrame(step);
    }

    requestAnimationFrame(step);
}

function buildLookups(data) {
    attackPathEdges.clear();
    cycleEdges.clear();
    criticalNodeIds.clear();

    for (const path of (data.attack_paths || [])) {
        const nodes = path.path_nodes || [];
        for (let i = 0; i < nodes.length - 1; i++) {
            attackPathEdges.add(`${nodes[i]}|${nodes[i + 1]}`);
        }
    }

    for (const cycle of (data.cycles || [])) {
        const ids = cycle.node_ids || [];
        for (let i = 0; i < ids.length; i++) {
            cycleEdges.add(`${ids[i]}|${ids[(i + 1) % ids.length]}`);
        }
    }

    if (data.critical_node && data.critical_node.top_nodes) {
        for (const n of data.critical_node.top_nodes) {
            criticalNodeIds.add(n.id);
        }
    }
}

// ─── Path Cards ─────────────────────────────────────────────────────────────

function renderPathCards(paths) {
    const list = document.getElementById('paths-list');
    list.innerHTML = '';

    if (paths.length === 0) {
        list.innerHTML = `
            <div class="empty-state">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                <p>No attack paths detected</p>
            </div>`;
        return;
    }

    paths.forEach((path, idx) => {
        const card = document.createElement('div');
        card.className = 'path-card';
        card.dataset.index = idx;

        const names = (path.path_names || []).join(' → ');
        const severity = path.severity || 'LOW';

        card.innerHTML = `
            <div class="path-card-header">
                <span class="path-card-title">Path #${idx + 1}</span>
                <span class="severity-badge severity-${severity}">${severity}</span>
            </div>
            <div class="path-card-route">${names}</div>
        `;

        card.addEventListener('click', () => togglePathHighlight(idx));
        list.appendChild(card);
    });
}

function togglePathHighlight(idx) {
    const cards = document.querySelectorAll('.path-card');

    if (activePathIdx === idx) {
        activePathIdx = null;
        cards.forEach(c => c.classList.remove('active'));
        clearHighlight();
        return;
    }

    activePathIdx = idx;
    cards.forEach(c => c.classList.remove('active'));
    cards[idx].classList.add('active');

    const path = graphData.attack_paths[idx];
    const pathNodeSet = new Set(path.path_nodes || []);
    const pathEdgeSet = new Set();
    const nodes = path.path_nodes || [];
    for (let i = 0; i < nodes.length - 1; i++) {
        pathEdgeSet.add(`${nodes[i]}|${nodes[i + 1]}`);
    }

    d3.selectAll('.node-circle')
        .classed('dimmed', d => !pathNodeSet.has(d.id));
    d3.selectAll('.node-label')
        .classed('dimmed', d => !pathNodeSet.has(d.id));
    d3.selectAll('.link-line')
        .classed('dimmed', d => !pathEdgeSet.has(`${d.source.id || d.source}|${d.target.id || d.target}`));
}

function clearHighlight() {
    activePathIdx = null;
    d3.selectAll('.dimmed').classed('dimmed', false);
    document.querySelectorAll('.path-card').forEach(c => c.classList.remove('active'));
}

// ─── Graph Rendering ────────────────────────────────────────────────────────

function renderGraph(data) {
    const width  = document.getElementById('graph-container').clientWidth;
    const height = document.getElementById('graph-container').clientHeight;

    linkGroup.selectAll('*').remove();
    nodeGroup.selectAll('*').remove();
    labelGroup.selectAll('*').remove();

    if (simulation) simulation.stop();

    const nodes = data.nodes.map(d => ({ ...d }));
    const edges = data.edges.map(d => ({ ...d }));

    // Force Simulation
    simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(edges)
            .id(d => d.id)
            .distance(d => 80 + (d.weight || 1) * 10)
            .strength(0.4)
        )
        .force('charge', d3.forceManyBody()
            .strength(-300)
            .distanceMax(500)
        )
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(22))
        .force('x', d3.forceX(width / 2).strength(0.05))
        .force('y', d3.forceY(height / 2).strength(0.05))
        .alphaDecay(0.02)
        .velocityDecay(0.4);

    // Edges
    const links = linkGroup.selectAll('line')
        .data(edges)
        .enter()
        .append('line')
        .attr('class', d => {
            const key = `${d.source.id || d.source}|${d.target.id || d.target}`;
            let cls = 'link-line';
            if (attackPathEdges.has(key)) cls += ' attack-path-edge';
            if (cycleEdges.has(key)) cls += ' cycle-edge';
            return cls;
        })
        .attr('marker-end', d => {
            const key = `${d.source.id || d.source}|${d.target.id || d.target}`;
            if (attackPathEdges.has(key)) return 'url(#arrowhead-attack)';
            if (cycleEdges.has(key)) return 'url(#arrowhead-cycle)';
            return 'url(#arrowhead)';
        });

    // Nodes
    const circles = nodeGroup.selectAll('circle')
        .data(nodes)
        .enter()
        .append('circle')
        .attr('class', d => {
            let cls = 'node-circle';
            if (d.is_source) cls += ' source-node';
            if (d.is_sink) cls += ' sink-node';
            if (criticalNodeIds.has(d.id)) cls += ' critical-node';
            return cls;
        })
        .attr('r', d => getNodeRadius(d))
        .attr('fill', d => NODE_COLORS[d.type] || DEFAULT_NODE_COLOR)
        .attr('stroke', d => {
            if (criticalNodeIds.has(d.id)) return CRITICAL_NODE_COLOR;
            if (d.is_source) return '#22c55e';
            if (d.is_sink) return '#f43f5e';
            return 'rgba(255,255,255,0.1)';
        })
        .style('filter', d => criticalNodeIds.has(d.id) ? 'url(#glow)' : 'none')
        .call(d3.drag()
            .on('start', dragStarted)
            .on('drag', dragged)
            .on('end', dragEnded)
        )
        .on('mouseover', showTooltip)
        .on('mousemove', moveTooltip)
        .on('mouseout', hideTooltip)
        .on('click', onNodeClick);

    // Labels
    const labels = labelGroup.selectAll('text')
        .data(nodes)
        .enter()
        .append('text')
        .attr('class', 'node-label')
        .attr('dy', d => getNodeRadius(d) + 13)
        .text(d => d.name);

    // Tick
    simulation.on('tick', () => {
        links
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);
        circles
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);
        labels
            .attr('x', d => d.x)
            .attr('y', d => d.y);
    });

    updateVisibility();
    setTimeout(zoomToFit, 120);
}

// ─── Zoom ───────────────────────────────────────────────────────────────────

function zoomIn() {
    svg.transition().duration(300).call(zoom.scaleBy, 1.4);
}

function zoomOut() {
    svg.transition().duration(300).call(zoom.scaleBy, 0.7);
}

function resetZoom() {
    zoomToFit();
}

function zoomToFit() {
    if (!graphData || !graphData.nodes) return;

    const bounds = gMain.node().getBBox();
    const parent = svg.node();
    const fullWidth = parent.clientWidth;
    const fullHeight = parent.clientHeight;

    const width = bounds.width;
    const height = bounds.height;
    const midX = bounds.x + width / 2;
    const midY = bounds.y + height / 2;

    if (width === 0 || height === 0) return;

    const scale = 0.82 / Math.max(width / fullWidth, height / fullHeight);
    const translate = [fullWidth / 2 - scale * midX, fullHeight / 2 - scale * midY];

    svg.transition()
        .duration(700)
        .ease(d3.easeCubicInOut)
        .call(zoom.transform, d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale));
}

function getNodeRadius(d) {
    if (criticalNodeIds.has(d.id)) return CRITICAL_RADIUS;
    if (d.is_source) return SOURCE_RADIUS;
    if (d.is_sink) return SINK_RADIUS;
    return BASE_RADIUS;
}

// ─── Drag ───────────────────────────────────────────────────────────────────

function dragStarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragEnded(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}

// ─── Tooltip ────────────────────────────────────────────────────────────────

function showTooltip(event, d) {
    const tooltip = document.getElementById('tooltip');
    tooltip.classList.remove('hidden');

    document.getElementById('tooltip-name').textContent      = d.name;
    document.getElementById('tooltip-type').textContent       = d.type;
    document.getElementById('tooltip-namespace').textContent  = d.namespace || '—';
    document.getElementById('tooltip-risk').textContent       = ((d.risk_score || 0)).toFixed(1);
    document.getElementById('tooltip-cves').textContent       = (d.cves && d.cves.length > 0) ? d.cves.join(', ') : 'None';

    let role = [];
    if (d.is_source) role.push('Source');
    if (d.is_sink) role.push('Sink');
    if (criticalNodeIds.has(d.id)) role.push('Critical');
    document.getElementById('tooltip-role').textContent = role.length > 0 ? role.join(', ') : 'Intermediate';
}

function moveTooltip(event) {
    const tooltip = document.getElementById('tooltip');
    const rect = document.getElementById('graph-container').getBoundingClientRect();
    let x = event.clientX - rect.left + 15;
    let y = event.clientY - rect.top + 15;
    if (x + 240 > rect.width) x = event.clientX - rect.left - 240;
    if (y + 170 > rect.height) y = event.clientY - rect.top - 170;
    tooltip.style.left = x + 'px';
    tooltip.style.top  = y + 'px';
}

function hideTooltip() {
    document.getElementById('tooltip').classList.add('hidden');
}

// ─── Node Click ─────────────────────────────────────────────────────────────

function onNodeClick(event, d) {
    event.stopPropagation();

    if (selectedNode === d.id) {
        selectedNode = null;
        clearHighlight();
        document.getElementById('detail-panel').classList.add('hidden');
        return;
    }

    selectedNode = d.id;
    clearHighlight();

    const reachable = bfsReachable(d.id);
    reachable.add(d.id);

    d3.selectAll('.node-circle').classed('dimmed', n => !reachable.has(n.id));
    d3.selectAll('.node-label').classed('dimmed', n => !reachable.has(n.id));
    d3.selectAll('.link-line').classed('dimmed', e => {
        const srcId = e.source.id || e.source;
        return !reachable.has(srcId);
    });

    showDetailPanel(d);
}

function bfsReachable(startId) {
    const visited = new Set();
    const queue = [startId];
    visited.add(startId);

    const adjList = {};
    for (const edge of (graphData.edges || [])) {
        if (!adjList[edge.source]) adjList[edge.source] = [];
        adjList[edge.source].push(edge.target);
    }

    while (queue.length > 0) {
        const current = queue.shift();
        for (const neighbor of (adjList[current] || [])) {
            if (!visited.has(neighbor)) {
                visited.add(neighbor);
                queue.push(neighbor);
            }
        }
    }

    return visited;
}

// ─── Detail Panel ───────────────────────────────────────────────────────────

function showDetailPanel(d) {
    const panel   = document.getElementById('detail-panel');
    const title   = document.getElementById('detail-title');
    const content = document.getElementById('detail-content');

    panel.classList.remove('hidden');
    title.textContent = d.name;

    const isCritical = criticalNodeIds.has(d.id);
    let criticalInfo = '';
    if (isCritical && graphData.critical_node) {
        const cn = graphData.critical_node.top_nodes.find(n => n.id === d.id);
        if (cn) {
            criticalInfo = `
                <div class="detail-section">
                    <div class="detail-section-title">Critical Node Impact</div>
                    <div class="detail-row">
                        <span class="detail-row-key">Paths Eliminated</span>
                        <span class="detail-row-value" style="color: var(--accent-gold)">${cn.paths_eliminated} / ${graphData.critical_node.baseline_paths}</span>
                    </div>
                </div>
            `;
        }
    }

    const outEdges = (graphData.edges || []).filter(e => e.source === d.id);
    const inEdges  = (graphData.edges || []).filter(e => e.target === d.id);
    const pathsThrough = (graphData.attack_paths || []).filter(
        p => (p.path_nodes || []).includes(d.id)
    );

    const riskPct = Math.min(((d.risk_score || 0) / 10) * 100, 100);
    const riskColor = (d.risk_score || 0) > 7 ? 'var(--accent-red)' :
                      (d.risk_score || 0) > 4 ? 'var(--accent-orange)' : 'var(--accent-green)';

    content.innerHTML = `
        <div class="detail-section">
            <div class="detail-section-title">Properties</div>
            <div class="detail-row">
                <span class="detail-row-key">Type</span>
                <span class="detail-row-value">${d.type}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-key">Namespace</span>
                <span class="detail-row-value">${d.namespace || '—'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-key">ID</span>
                <span class="detail-row-value" style="font-size:0.68rem; word-break:break-all; max-width:180px">${d.id}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-key">Risk Score</span>
                <span class="detail-row-value" style="color:${riskColor}">${(d.risk_score || 0).toFixed(1)} / 10</span>
            </div>
            <div class="risk-bar">
                <div class="risk-bar-fill" style="width:${riskPct}%; background:${riskColor}"></div>
            </div>
            <div class="detail-row">
                <span class="detail-row-key">Role</span>
                <span class="detail-row-value">${d.is_source ? 'Source' : ''} ${d.is_sink ? 'Sink' : ''} ${!d.is_source && !d.is_sink ? 'Intermediate' : ''}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-key">CVEs</span>
                <span class="detail-row-value">${d.cves && d.cves.length > 0 ? d.cves.join(', ') : 'None'}</span>
            </div>
        </div>

        ${criticalInfo}

        <div class="detail-section">
            <div class="detail-section-title">Connections (${outEdges.length} out, ${inEdges.length} in)</div>
            <ul class="detail-list">
                ${outEdges.map(e => {
                    const targetNode = graphData.nodes.find(n => n.id === e.target);
                    const targetName = targetNode ? targetNode.name : e.target;
                    return `<li><strong>→ ${targetName}</strong> (${e.relationship})</li>`;
                }).join('')}
                ${inEdges.map(e => {
                    const sourceNode = graphData.nodes.find(n => n.id === e.source);
                    const sourceName = sourceNode ? sourceNode.name : e.source;
                    return `<li><strong>← ${sourceName}</strong> (${e.relationship})</li>`;
                }).join('')}
            </ul>
        </div>

        <div class="detail-section">
            <div class="detail-section-title">Attack Paths Through (${pathsThrough.length})</div>
            <ul class="detail-list">
                ${pathsThrough.map((p) => {
                    const names = (p.path_names || []).join(' → ');
                    return `<li><span class="severity-badge severity-${p.severity}" style="margin-right:5px">${p.severity}</span> ${names}</li>`;
                }).join('') || '<li>No attack paths pass through this node.</li>'}
            </ul>
        </div>
    `;
}

// ─── Toggle Visibility ──────────────────────────────────────────────────────

function updateVisibility() {
    const showPaths    = document.getElementById('toggle-paths').checked;
    const showCycles   = document.getElementById('toggle-cycles').checked;
    const showLabels   = document.getElementById('toggle-labels').checked;
    const showCritical = document.getElementById('toggle-critical').checked;

    d3.selectAll('.attack-path-edge')
        .style('visibility', showPaths ? 'visible' : 'hidden');

    d3.selectAll('.cycle-edge')
        .style('visibility', showCycles ? 'visible' : 'hidden');

    d3.selectAll('.node-label')
        .style('display', showLabels ? 'block' : 'none');

    d3.selectAll('.critical-node')
        .style('filter', showCritical ? 'url(#glow)' : 'none')
        .attr('stroke', d => {
            if (!showCritical && criticalNodeIds.has(d.id)) return 'rgba(255,255,255,0.1)';
            if (criticalNodeIds.has(d.id)) return CRITICAL_NODE_COLOR;
            if (d.is_source) return '#22c55e';
            if (d.is_sink) return '#f43f5e';
            return 'rgba(255,255,255,0.1)';
        })
        .attr('r', d => {
            if (!showCritical && criticalNodeIds.has(d.id)) return BASE_RADIUS;
            return getNodeRadius(d);
        });
}

// ─── SVG Click to deselect ──────────────────────────────────────────────────

document.addEventListener('click', (e) => {
    if (e.target.id === 'graph-svg' || e.target.closest('#graph-svg') === document.getElementById('graph-svg')) {
        if (e.target.tagName !== 'circle') {
            clearHighlight();
            selectedNode = null;
        }
    }
});
