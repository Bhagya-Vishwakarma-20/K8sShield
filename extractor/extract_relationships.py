#!/usr/bin/env python3
"""
Kubernetes Cluster Graph Generator
Reads cluster.json (produced by collect_all_resources.py) and generates a
cluster-graph.json file with nodes and edges in the same format as
mock-cluster-graph.json.

CVE data is fetched from the NVD API for container images and from pod/deployment
labels (e.g., cve: "CVE-2023-5678").

Usage:
    python extract_relationships.py
    python extract_relationships.py --input k8s_resources/cluster.json --output cluster-graph.json
"""

import json
import os
import re
import sys
import time
import hashlib
import argparse
import requests
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Set


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_RATE_LIMIT_DELAY = 0.6
CACHE_DIR = ".nvd_cache"
CACHE_VALIDITY_DAYS = 30
REQUEST_TIMEOUT = 30

SYSTEM_NAMESPACES = {
    'kube-system', 'kube-node-lease', 'kube-public',
    'kube-apiserver', 'local-path-storage'
}
SYSTEM_PREFIXES = ('kube-', 'system:', 'kubeadm:')
SYSTEM_SA_NAMES = {'default'}
SYSTEM_CONFIGMAPS = {'kube-root-ca.crt'}

# Built-in Kubernetes / infrastructure ClusterRoles to exclude
BUILTIN_CLUSTERROLES = {
    'admin', 'cluster-admin', 'edit', 'view',
    'kindnet', 'local-path-provisioner-role',
}


# ─────────────────────────────────────────────
# NVD Cache Manager (from k8s_risk_calculator.py)
# ─────────────────────────────────────────────
class NVDCacheManager:
    """Manages caching of NVD API responses to minimize rate limiting"""

    def __init__(self, cache_dir: str = CACHE_DIR):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

    def _get_cache_path(self, key: str) -> Path:
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.json"

    def _is_cache_valid(self, cache_file: Path) -> bool:
        if not cache_file.exists():
            return False
        mtime = cache_file.stat().st_mtime
        age_days = (time.time() - mtime) / (60 * 60 * 24)
        return age_days < CACHE_VALIDITY_DAYS

    def get(self, key: str) -> Optional[Dict]:
        cache_file = self._get_cache_path(key)
        if self._is_cache_valid(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return None
        return None

    def set(self, key: str, value: Dict) -> None:
        try:
            cache_file = self._get_cache_path(key)
            with open(cache_file, 'w') as f:
                json.dump(value, f)
        except IOError as e:
            print(f"  [WARN] Failed to write cache: {e}")


# ─────────────────────────────────────────────
# CVE Fetcher (from k8s_risk_calculator.py)
# ─────────────────────────────────────────────
class CVEFetcher:
    """Fetches CVE data from NVD API with caching and rate limiting"""

    def __init__(self, cache_manager: NVDCacheManager, api_key: str = None):
        self.cache_manager = cache_manager
        self.last_request_time = 0
        self.api_key = api_key
        self.session = requests.Session()
        headers = {'User-Agent': 'K8s-Cluster-Graph-Generator/1.0'}
        if api_key:
            headers['apiKey'] = api_key
        self.session.headers.update(headers)

    def _rate_limit(self) -> None:
        elapsed = time.time() - self.last_request_time
        if elapsed < API_RATE_LIMIT_DELAY:
            time.sleep(API_RATE_LIMIT_DELAY - elapsed)

    @staticmethod
    def _normalize_cve(cve_dict: Dict) -> Dict:
        """Normalize CVE dict to use consistent keys (handles old cache format)"""
        return {
            'cve_id': cve_dict.get('cve_id', ''),
            'cvss_score': cve_dict.get('cvss_score', cve_dict.get('cvss_v3_score', 0.0)),
            'cvss_severity': cve_dict.get('cvss_severity', cve_dict.get('cvss_v3_severity', 'UNKNOWN'))
        }

    def fetch_cve_by_id(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch a single CVE by its ID.
        Returns dict with cve_id, cvss_score, cvss_severity or None.
        """
        cache_key = f"nvd_cve_id_{cve_id}"
        cached = self.cache_manager.get(cache_key)
        if cached:
            return self._normalize_cve(cached)

        try:
            self._rate_limit()
            params = {'cveId': cve_id}
            response = self.session.get(
                NVD_API_BASE, params=params, timeout=REQUEST_TIMEOUT
            )
            self.last_request_time = time.time()

            if response.status_code == 200:
                data = response.json()
                vulns = data.get('vulnerabilities', [])
                if vulns:
                    parsed = self._parse_nvd_cve(vulns[0])
                    if parsed:
                        result = {
                            'cve_id': parsed['cve_id'],
                            'cvss_score': parsed['cvss_score'],
                            'cvss_severity': parsed['cvss_severity']
                        }
                        self.cache_manager.set(cache_key, result)
                        return result
            elif response.status_code == 403:
                print(f"  [WARN] NVD API rate limited for {cve_id}")
            elif response.status_code != 404:
                print(f"  [WARN] NVD API returned {response.status_code} for {cve_id}")

        except requests.exceptions.RequestException as e:
            print(f"  [WARN] Failed to fetch CVE {cve_id}: {e}")
        except (json.JSONDecodeError, KeyError) as e:
            print(f"  [WARN] Failed to parse NVD response for {cve_id}: {e}")

        # Cache empty result to avoid repeated lookups
        empty = {'cve_id': cve_id, 'cvss_score': 0.0, 'cvss_severity': 'UNKNOWN'}
        self.cache_manager.set(cache_key, empty)
        return empty

    def fetch_cves_by_keyword(self, keyword: str, max_results: int = 20) -> List[Dict]:
        """
        Fetch CVEs by keyword (e.g., image name + version).
        Returns list of dicts with cve_id, cvss_score, cvss_severity.
        """
        cache_key = f"nvd_keyword_{keyword}"
        cached = self.cache_manager.get(cache_key)
        if cached:
            return [self._normalize_cve(c) for c in cached.get('cves', [])]

        cves = []
        try:
            self._rate_limit()
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': max_results,
                'startIndex': 0
            }
            response = self.session.get(
                NVD_API_BASE, params=params, timeout=REQUEST_TIMEOUT
            )
            self.last_request_time = time.time()

            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    parsed = self._parse_nvd_cve(vuln)
                    if parsed:
                        cves.append(parsed)

            self.cache_manager.set(cache_key, {
                'cves': cves,
                'fetched_at': datetime.now().isoformat()
            })

        except requests.exceptions.RequestException as e:
            print(f"  [WARN] Failed to fetch CVEs for '{keyword}': {e}")
        except (json.JSONDecodeError, KeyError) as e:
            print(f"  [WARN] Failed to parse NVD response for '{keyword}': {e}")

        return cves

    @staticmethod
    def _parse_nvd_cve(vuln: Dict) -> Optional[Dict]:
        """Parse CVE data from NVD API response, filters out old CVEs (>5 years)"""
        try:
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id')

            cvss_score = 0.0
            cvss_severity = "UNKNOWN"

            metrics = cve_data.get('metrics', {})
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_severity = cvss_data.get('baseSeverity', "UNKNOWN")
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_severity = cvss_data.get('baseSeverity', "UNKNOWN")
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                # V2 doesn't have baseSeverity in cvssData, derive from score
                if cvss_score >= 9.0:
                    cvss_severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    cvss_severity = "HIGH"
                elif cvss_score >= 4.0:
                    cvss_severity = "MEDIUM"
                else:
                    cvss_severity = "LOW"

            published_date = cve_data.get('published', '')
            if published_date:
                try:
                    pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                    cutoff_date = datetime.now(pub_date.tzinfo) - timedelta(days=5 * 365)
                    if pub_date < cutoff_date:
                        return None
                except (ValueError, TypeError):
                    pass

            if cve_id and cvss_score > 0:
                return {
                    'cve_id': cve_id,
                    'cvss_score': cvss_score,
                    'cvss_severity': cvss_severity
                }
        except (KeyError, IndexError, TypeError):
            pass
        return None


# ─────────────────────────────────────────────
# Image Utilities
# ─────────────────────────────────────────────
def extract_image_components(image: str) -> Tuple[str, Optional[str]]:
    """
    Extract image name and version from container image string.
    'nginx:1.21' → ('nginx', '1.21')
    'node:16-alpine' → ('node', '16')
    'gcr.io/project/app:v1.0' → ('app', '1.0')
    """
    parts = image.split(':')
    image_path = parts[0]
    tag = parts[1] if len(parts) > 1 else None

    image_name = image_path.split('/')[-1]

    version = None
    if tag:
        version = tag.split('-')[0]
        if version.startswith('v'):
            version = version[1:]

    return image_name, version


# ─────────────────────────────────────────────
# Resource Filtering
# ─────────────────────────────────────────────
def is_system_resource(name: str, namespace: str, resource_type: str = '') -> bool:
    """Check if a resource is a system/internal resource that should be filtered"""
    if namespace in SYSTEM_NAMESPACES:
        return True
    if any(name.startswith(prefix) for prefix in SYSTEM_PREFIXES):
        return True
    if resource_type == 'ConfigMap' and name in SYSTEM_CONFIGMAPS:
        return True
    return False


def make_node_id(resource_type: str, name: str, namespace: str) -> str:
    """
    Generate a unique, readable node ID.
    Format: <type-prefix>-<name> (namespace appended if needed for uniqueness).
    """
    prefix_map = {
        'Pod': 'pod',
        'Service': 'svc',
        'Deployment': 'deploy',
        'ServiceAccount': 'sa',
        'Secret': 'secret',
        'ConfigMap': 'cm',
        'Role': 'role',
        'RoleBinding': 'rb',
        'ClusterRole': 'cr',
        'ClusterRoleBinding': 'crb',
        'Node': 'node',
        'Namespace': 'ns',
        'NetworkPolicy': 'netpol',
    }
    prefix = prefix_map.get(resource_type, resource_type.lower())

    # Shorten long pod names (e.g., "backend-api-5fbff55f44-8wtb2" → "backend-api-5fbff55f44-8wtb2")
    return f"{prefix}-{name}"


# ─────────────────────────────────────────────
# Risk Score Heuristics
# ─────────────────────────────────────────────
def calculate_secret_risk(name: str, labels: Dict) -> float:
    """Calculate risk score for a secret based on name patterns and labels"""
    sensitivity = labels.get('sensitivity', '').lower()
    crown_jewel = labels.get('crown-jewel', 'false').lower()

    if crown_jewel == 'true':
        return 10.0

    high_risk_patterns = ['admin', 'token', 'cred', 'password', 'key', 'tls', 'cert']
    if any(p in name.lower() for p in high_risk_patterns):
        if sensitivity == 'high' or sensitivity == 'critical':
            return 9.5
        return 8.0

    if sensitivity == 'high':
        return 8.0
    elif sensitivity == 'medium':
        return 6.0
    return 5.0


def calculate_role_risk(rules: List[Dict]) -> float:
    """Calculate risk score for a Role/ClusterRole based on RBAC rules"""
    risk = 3.0
    for rule in rules:
        resources = rule.get('resources', [])
        verbs = rule.get('verbs', [])

        if '*' in resources or '*' in verbs:
            return 10.0
        if 'pods/exec' in resources and any(v in verbs for v in ['get', 'create']):
            risk = max(risk, 8.5)
        if 'secrets' in resources and any(v in verbs for v in ['get', 'list']):
            risk = max(risk, 7.0)
        if 'pods' in resources and any(v in verbs for v in ['get', 'list', 'create', 'delete']):
            risk = max(risk, 5.0)
        if 'configmaps' in resources:
            risk = max(risk, 4.0)

    return min(risk, 10.0)


def calculate_service_risk(service: Dict) -> float:
    """Calculate risk score for a Service"""
    svc_type = service.get('spec', {}).get('type', 'ClusterIP')
    if svc_type == 'LoadBalancer':
        return 7.5
    elif svc_type == 'NodePort':
        return 6.5
    return 4.0


def calculate_sa_risk(labels: Dict) -> float:
    """Calculate risk score for a ServiceAccount based on labels"""
    risk_label = labels.get('risk', '').lower()
    if risk_label == 'critical':
        return 9.0
    elif risk_label == 'high':
        return 7.0
    elif risk_label == 'medium':
        return 5.0
    return 3.5


# ─────────────────────────────────────────────
# Cluster Graph Builder
# ─────────────────────────────────────────────
class ClusterGraphBuilder:
    """
    Builds a cluster graph (nodes + edges) from cluster.json data.
    Output matches mock-cluster-graph.json format.
    """

    def __init__(self, cluster_data: Dict, cve_fetcher: CVEFetcher):
        self.data = cluster_data
        self.cve_fetcher = cve_fetcher

        # Node storage: id → node dict
        self.nodes: Dict[str, Dict] = {}
        # Edge storage: list of edge dicts
        self.edges: List[Dict] = []
        # Track CVEs per pod (for edge enrichment)
        self.pod_cves: Dict[str, List[Dict]] = {}  # node_id → [{ cve_id, cvss_score }]
        # Track all node IDs for deduplication
        self._seen_ids: Set[str] = set()

        # Lookup maps for building edges
        self._pods_by_ns: Dict[str, List[Dict]] = defaultdict(list)
        self._services_by_ns: Dict[str, List[Dict]] = defaultdict(list)
        self._deployments_by_ns: Dict[str, List[Dict]] = defaultdict(list)
        self._roles_by_ns: Dict[str, List[Dict]] = defaultdict(list)
        self._rolebindings_by_ns: Dict[str, List[Dict]] = defaultdict(list)
        self._serviceaccounts_by_ns: Dict[str, List[Dict]] = defaultdict(list)
        self._secrets_by_ns: Dict[str, List[Dict]] = defaultdict(list)
        self._configmaps_by_ns: Dict[str, List[Dict]] = defaultdict(list)
        self._networkpolicies_by_ns: Dict[str, List[Dict]] = defaultdict(list)

    def _ensure_unique_id(self, base_id: str, namespace: str) -> str:
        """Ensure node IDs are unique by appending namespace if needed"""
        node_id = base_id
        if node_id in self._seen_ids:
            node_id = f"{base_id}-{namespace}"
        if node_id in self._seen_ids:
            # Last resort: append counter
            i = 2
            while f"{node_id}-{i}" in self._seen_ids:
                i += 1
            node_id = f"{node_id}-{i}"
        self._seen_ids.add(node_id)
        return node_id

    def _add_node(self, node_id: str, resource_type: str, name: str,
                  namespace: str, risk_score: float,
                  is_source: bool = False, is_sink: bool = False,
                  cves: List[str] = None):
        """Add a node to the graph"""
        if node_id in self.nodes:
            return  # already added
        self.nodes[node_id] = {
            "id": node_id,
            "type": resource_type,
            "name": name,
            "namespace": namespace,
            "risk_score": round(risk_score, 1),
            "is_source": is_source,
            "is_sink": is_sink,
            "cves": cves or []
        }

    def _add_edge(self, source_id: str, target_id: str, relationship: str,
                  weight: float, cve: str = None, cvss: float = None):
        """Add an edge to the graph"""
        # Only add if both nodes exist
        if source_id not in self.nodes or target_id not in self.nodes:
            return
        self.edges.append({
            "source": source_id,
            "target": target_id,
            "relationship": relationship,
            "weight": round(weight, 1),
            "cve": cve,
            "cvss": round(cvss, 1) if cvss else None
        })

    # ─── Node Builders ────────────────────────

    def _build_namespace_nodes(self):
        """Build Namespace nodes"""
        print("[*] Building Namespace nodes...")
        namespaces = self.data.get('metadata', {}).get('namespaces', [])
        count = 0
        for ns in namespaces:
            if ns in SYSTEM_NAMESPACES:
                continue
            node_id = make_node_id('Namespace', ns, 'cluster')
            is_sink = False
            risk = 4.0
            self._add_node(node_id, 'Namespace', ns, 'cluster', risk,
                           is_source=False, is_sink=is_sink)
            count += 1
        print(f"  [OK] {count} Namespace nodes")

    def _build_node_nodes(self):
        """Build Node (k8s worker/master) nodes"""
        print("[*] Building Node nodes...")
        cluster_data = self.data.get('cluster_resources', {})
        k8s_nodes = cluster_data.get('resources', {}).get('nodes', {}).get('items', [])
        count = 0
        for node in k8s_nodes:
            name = node.get('metadata', {}).get('name', '')
            if is_system_resource(name, '', 'Node'):
                continue
            node_id = make_node_id('Node', name, 'cluster')
            self._add_node(node_id, 'Node', name, 'cluster', 9.0,
                           is_source=False, is_sink=True)
            count += 1
        print(f"  [OK] {count} Node nodes")

    def _build_pod_nodes(self):
        """Build Pod nodes with CVE lookups"""
        print("[*] Building Pod nodes (with CVE lookups)...")
        count = 0
        unique_images_queried = set()

        for ns_data in self.data.get('namespaced_resources', []):
            namespace = ns_data.get('namespace')
            if namespace in SYSTEM_NAMESPACES:
                continue

            raw_pods = ns_data.get('resources', {}).get('pods', {}).get('items', [])
            # Filter to avoid transient temporal snapshots for Pending/Creating pods
            pods = [
                p for p in raw_pods
                if p.get('status', {}).get('phase') in ('Running', 'Succeeded')
            ]
            self._pods_by_ns[namespace] = pods

            for pod in pods:
                pod_name = pod.get('metadata', {}).get('name', '')
                labels = pod.get('metadata', {}).get('labels', {})
                node_id = make_node_id('Pod', pod_name, namespace)
                node_id = self._ensure_unique_id(node_id, namespace)

                # Collect CVEs from labels
                cve_ids = []
                label_cve = labels.get('cve', '')
                if label_cve and label_cve.startswith('CVE-'):
                    cve_ids.append(label_cve)

                # Collect CVEs from container images via NVD
                images = []
                for container in pod.get('spec', {}).get('containers', []):
                    img = container.get('image', '')
                    if img:
                        images.append(img)

                image_cves = []
                for img in images:
                    img_name, img_version = extract_image_components(img)
                    keyword = f"{img_name} {img_version}" if img_version else img_name
                    if keyword not in unique_images_queried:
                        unique_images_queried.add(keyword)
                        print(f"  → Querying NVD for '{keyword}'...", end=" ", flush=True)
                        fetched = self.cve_fetcher.fetch_cves_by_keyword(keyword, max_results=5)
                        print(f"({len(fetched)} CVEs)")
                        image_cves.extend(fetched)
                    else:
                        # Re-use cached
                        fetched = self.cve_fetcher.fetch_cves_by_keyword(keyword, max_results=5)
                        image_cves.extend(fetched)

                # Merge image CVE IDs
                for ic in image_cves:
                    if ic['cve_id'] not in cve_ids:
                        cve_ids.append(ic['cve_id'])

                # Fetch CVSS for label CVEs
                all_cvss = [ic['cvss_score'] for ic in image_cves]
                if label_cve and label_cve.startswith('CVE-'):
                    cve_info = self.cve_fetcher.fetch_cve_by_id(label_cve)
                    if cve_info and cve_info.get('cvss_score', 0) > 0:
                        all_cvss.append(cve_info['cvss_score'])

                # Store for edge enrichment
                pod_cve_details = []
                for ic in image_cves:
                    pod_cve_details.append({
                        'cve_id': ic['cve_id'],
                        'cvss_score': ic['cvss_score']
                    })
                if label_cve and label_cve.startswith('CVE-'):
                    cve_info = self.cve_fetcher.fetch_cve_by_id(label_cve)
                    if cve_info:
                        pod_cve_details.append({
                            'cve_id': cve_info['cve_id'],
                            'cvss_score': cve_info.get('cvss_score', 0.0)
                        })
                self.pod_cves[node_id] = pod_cve_details

                # Risk score: based on max CVSS + baseline
                max_cvss = max(all_cvss) if all_cvss else 0.0
                risk = max(3.0, max_cvss * 0.8) if max_cvss > 0 else 4.0

                # Boost if pod has label-indicated CVE with CVSS
                cvss_label = labels.get('cvss', '')
                if cvss_label:
                    try:
                        risk = max(risk, float(cvss_label) * 0.9)
                    except ValueError:
                        pass

                self._add_node(node_id, 'Pod', pod_name, namespace, risk,
                               is_source=False, is_sink=False, cves=cve_ids)
                count += 1

        print(f"  [OK] {count} Pod nodes")

    def _build_service_nodes(self):
        """Build Service nodes"""
        print("[*] Building Service nodes...")
        count = 0
        for ns_data in self.data.get('namespaced_resources', []):
            namespace = ns_data.get('namespace')
            if namespace in SYSTEM_NAMESPACES:
                continue

            services = ns_data.get('resources', {}).get('services', {}).get('items', [])
            self._services_by_ns[namespace] = services

            for svc in services:
                name = svc.get('metadata', {}).get('name', '')
                if is_system_resource(name, namespace, 'Service'):
                    continue
                node_id = make_node_id('Service', name, namespace)
                node_id = self._ensure_unique_id(node_id, namespace)
                svc_type = svc.get('spec', {}).get('type', 'ClusterIP')
                is_source = svc_type in ('LoadBalancer', 'NodePort')
                risk = calculate_service_risk(svc)

                self._add_node(node_id, 'Service', name, namespace, risk,
                               is_source=is_source, is_sink=False)
                count += 1
        print(f"  [OK] {count} Service nodes")

    def _build_deployment_nodes(self):
        """Build Deployment nodes"""
        print("[*] Building Deployment nodes...")
        count = 0
        for ns_data in self.data.get('namespaced_resources', []):
            namespace = ns_data.get('namespace')
            if namespace in SYSTEM_NAMESPACES:
                continue

            deployments = ns_data.get('resources', {}).get('deployments', {}).get('items', [])
            self._deployments_by_ns[namespace] = deployments

            for dep in deployments:
                name = dep.get('metadata', {}).get('name', '')
                if is_system_resource(name, namespace, 'Deployment'):
                    continue
                node_id = make_node_id('Deployment', name, namespace)
                node_id = self._ensure_unique_id(node_id, namespace)
                risk = 4.0
                self._add_node(node_id, 'Deployment', name, namespace, risk,
                               is_source=False, is_sink=False)
                count += 1
        print(f"  [OK] {count} Deployment nodes")

    def _build_serviceaccount_nodes(self):
        """Build ServiceAccount nodes"""
        print("[*] Building ServiceAccount nodes...")
        count = 0
        for ns_data in self.data.get('namespaced_resources', []):
            namespace = ns_data.get('namespace')
            if namespace in SYSTEM_NAMESPACES:
                continue

            sas = ns_data.get('resources', {}).get('serviceaccounts', {}).get('items', [])
            self._serviceaccounts_by_ns[namespace] = sas

            for sa in sas:
                name = sa.get('metadata', {}).get('name', '')
                labels = sa.get('metadata', {}).get('labels', {})
                if is_system_resource(name, namespace, 'ServiceAccount'):
                    continue
                # Skip default SA unless it has special labels
                if name == 'default' and not labels.get('risk'):
                    continue
                node_id = make_node_id('ServiceAccount', name, namespace)
                node_id = self._ensure_unique_id(node_id, namespace)
                risk = calculate_sa_risk(labels)
                self._add_node(node_id, 'ServiceAccount', name, namespace, risk,
                               is_source=False, is_sink=False)
                count += 1
        print(f"  [OK] {count} ServiceAccount nodes")

    def _build_secret_nodes(self):
        """Build Secret nodes"""
        print("[*] Building Secret nodes...")
        count = 0
        for ns_data in self.data.get('namespaced_resources', []):
            namespace = ns_data.get('namespace')
            if namespace in SYSTEM_NAMESPACES:
                continue

            secrets = ns_data.get('resources', {}).get('secrets', {}).get('items', [])
            self._secrets_by_ns[namespace] = secrets

            for secret in secrets:
                name = secret.get('metadata', {}).get('name', '')
                labels = secret.get('metadata', {}).get('labels', {})
                if is_system_resource(name, namespace, 'Secret'):
                    continue
                node_id = make_node_id('Secret', name, namespace)
                node_id = self._ensure_unique_id(node_id, namespace)
                risk = calculate_secret_risk(name, labels)
                self._add_node(node_id, 'Secret', name, namespace, risk,
                               is_source=False, is_sink=False)
                count += 1
        print(f"  [OK] {count} Secret nodes")

    def _build_configmap_nodes(self):
        """Build ConfigMap nodes"""
        print("[*] Building ConfigMap nodes...")
        count = 0
        for ns_data in self.data.get('namespaced_resources', []):
            namespace = ns_data.get('namespace')
            if namespace in SYSTEM_NAMESPACES:
                continue

            configmaps = ns_data.get('resources', {}).get('configmaps', {}).get('items', [])
            self._configmaps_by_ns[namespace] = configmaps

            for cm in configmaps:
                name = cm.get('metadata', {}).get('name', '')
                labels = cm.get('metadata', {}).get('labels', {})
                if is_system_resource(name, namespace, 'ConfigMap'):
                    continue
                node_id = make_node_id('ConfigMap', name, namespace)
                node_id = self._ensure_unique_id(node_id, namespace)

                # Risk based on sensitivity and content
                sensitivity = labels.get('sensitivity', '').lower()
                cm_data = cm.get('data', {})
                has_db_info = any(
                    k.lower() in ('db_host', 'db_port', 'db_name', 'database_url', 'db_url')
                    for k in cm_data.keys()
                )
                if has_db_info:
                    risk = 5.5
                elif sensitivity == 'high':
                    risk = 5.0
                elif sensitivity == 'medium':
                    risk = 4.0
                else:
                    risk = 3.0

                self._add_node(node_id, 'ConfigMap', name, namespace, risk,
                               is_source=False, is_sink=False)
                count += 1
        print(f"  [OK] {count} ConfigMap nodes")

    def _build_role_nodes(self):
        """Build Role nodes"""
        print("[*] Building Role nodes...")
        count = 0
        for ns_data in self.data.get('namespaced_resources', []):
            namespace = ns_data.get('namespace')
            if namespace in SYSTEM_NAMESPACES:
                continue

            roles = ns_data.get('resources', {}).get('roles', {}).get('items', [])
            self._roles_by_ns[namespace] = roles

            for role in roles:
                name = role.get('metadata', {}).get('name', '')
                if is_system_resource(name, namespace, 'Role'):
                    continue
                node_id = make_node_id('Role', name, namespace)
                node_id = self._ensure_unique_id(node_id, namespace)
                rules = role.get('rules', [])
                risk = calculate_role_risk(rules)
                self._add_node(node_id, 'Role', name, namespace, risk,
                               is_source=False, is_sink=False)
                count += 1
        print(f"  [OK] {count} Role nodes")

    def _build_rolebinding_nodes(self):
        """Store RoleBindings for edge generation (no separate nodes in mock format)"""
        for ns_data in self.data.get('namespaced_resources', []):
            namespace = ns_data.get('namespace')
            if namespace in SYSTEM_NAMESPACES:
                continue
            rbs = ns_data.get('resources', {}).get('rolebindings', {}).get('items', [])
            self._rolebindings_by_ns[namespace] = rbs

    def _build_clusterrole_nodes(self):
        """Build ClusterRole nodes"""
        print("[*] Building ClusterRole nodes...")
        cluster_data = self.data.get('cluster_resources', {})
        clusterroles = cluster_data.get('resources', {}).get('clusterroles', {}).get('items', [])
        count = 0
        for cr in clusterroles:
            name = cr.get('metadata', {}).get('name', '')
            if name.startswith('system:') or name.startswith('kubeadm:'):
                continue
            if name in BUILTIN_CLUSTERROLES:
                continue
            node_id = make_node_id('ClusterRole', name, 'cluster')
            node_id = self._ensure_unique_id(node_id, 'cluster')
            rules = cr.get('rules', [])
            risk = calculate_role_risk(rules)
            self._add_node(node_id, 'ClusterRole', name, 'cluster', risk,
                           is_source=False, is_sink=False)
            count += 1
        print(f"  [OK] {count} ClusterRole nodes")

    def _build_clusterrolebinding_data(self):
        """Store ClusterRoleBindings for edge generation"""
        cluster_data = self.data.get('cluster_resources', {})
        self._clusterrolebindings = cluster_data.get(
            'resources', {}).get('clusterrolebindings', {}).get('items', [])

    def _build_networkpolicy_nodes(self):
        """Store NetworkPolicies for edge generation"""
        for ns_data in self.data.get('namespaced_resources', []):
            namespace = ns_data.get('namespace')
            if namespace in SYSTEM_NAMESPACES:
                continue
            netpols = ns_data.get('resources', {}).get('networkpolicies', {}).get('items', [])
            self._networkpolicies_by_ns[namespace] = netpols

    # ─── Edge Builders ────────────────────────

    def _get_best_cve_for_pod(self, pod_node_id: str) -> Tuple[Optional[str], Optional[float]]:
        """Get the highest-CVSS CVE for a pod (for edge enrichment)"""
        cves = self.pod_cves.get(pod_node_id, [])
        if not cves:
            return None, None
        best = max(cves, key=lambda x: x.get('cvss_score', 0))
        if best.get('cvss_score', 0) > 0:
            return best['cve_id'], best['cvss_score']
        return best.get('cve_id'), None

    def _find_node_id(self, resource_type: str, name: str, namespace: str) -> Optional[str]:
        """Find the node ID for a resource by type, name, namespace"""
        # Try direct match first
        base_id = make_node_id(resource_type, name, namespace)
        if base_id in self.nodes:
            return base_id
        # Try with namespace suffix
        ns_id = f"{base_id}-{namespace}"
        if ns_id in self.nodes:
            return ns_id
        # Search all nodes
        for nid, node in self.nodes.items():
            if (node['type'] == resource_type and
                    node['name'] == name and
                    node['namespace'] == namespace):
                return nid
        return None

    def _build_pod_sa_edges(self):
        """Pod → ServiceAccount (uses)"""
        print("[*] Building Pod → ServiceAccount edges...")
        count = 0
        for namespace, pods in self._pods_by_ns.items():
            for pod in pods:
                pod_name = pod.get('metadata', {}).get('name', '')
                sa_name = pod.get('spec', {}).get('serviceAccountName', '')
                if not sa_name or sa_name == 'default':
                    continue

                pod_id = self._find_node_id('Pod', pod_name, namespace)
                sa_id = self._find_node_id('ServiceAccount', sa_name, namespace)
                if pod_id and sa_id:
                    cve, cvss = self._get_best_cve_for_pod(pod_id)
                    self._add_edge(pod_id, sa_id, 'uses', 3.0, cve=cve, cvss=cvss)
                    count += 1
        print(f"  [OK] {count} edges")

    def _build_pod_secret_edges(self):
        """Pod → Secret (mounts / env-ref)"""
        print("[*] Building Pod → Secret edges...")
        count = 0
        for namespace, pods in self._pods_by_ns.items():
            for pod in pods:
                pod_name = pod.get('metadata', {}).get('name', '')
                pod_id = self._find_node_id('Pod', pod_name, namespace)
                if not pod_id:
                    continue

                # Volume secrets
                for volume in pod.get('spec', {}).get('volumes', []):
                    if 'secret' in volume:
                        secret_name = volume.get('secret', {}).get('secretName', '')
                        secret_id = self._find_node_id('Secret', secret_name, namespace)
                        if secret_id:
                            cve, cvss = self._get_best_cve_for_pod(pod_id)
                            self._add_edge(pod_id, secret_id, 'mounts', 4.0, cve=cve, cvss=cvss)
                            count += 1

                # Env var secrets
                for container in pod.get('spec', {}).get('containers', []):
                    for env_var in container.get('env', []):
                        secret_ref = env_var.get('valueFrom', {}).get('secretKeyRef')
                        if secret_ref:
                            secret_name = secret_ref.get('name', '')
                            secret_id = self._find_node_id('Secret', secret_name, namespace)
                            if secret_id:
                                cve, cvss = self._get_best_cve_for_pod(pod_id)
                                self._add_edge(pod_id, secret_id, 'reads', 3.5, cve=cve, cvss=cvss)
                                count += 1
        print(f"  [OK] {count} edges")

    def _build_pod_configmap_edges(self):
        """Pod → ConfigMap (reads)"""
        print("[*] Building Pod → ConfigMap edges...")
        count = 0
        for namespace, pods in self._pods_by_ns.items():
            for pod in pods:
                pod_name = pod.get('metadata', {}).get('name', '')
                pod_id = self._find_node_id('Pod', pod_name, namespace)
                if not pod_id:
                    continue

                # Volume configmaps
                for volume in pod.get('spec', {}).get('volumes', []):
                    if 'configMap' in volume:
                        cm_name = volume.get('configMap', {}).get('name', '')
                        cm_id = self._find_node_id('ConfigMap', cm_name, namespace)
                        if cm_id:
                            cve, cvss = self._get_best_cve_for_pod(pod_id)
                            self._add_edge(pod_id, cm_id, 'reads', 2.5, cve=cve, cvss=cvss)
                            count += 1

                    # Projected configmaps
                    if 'projected' in volume:
                        for source in volume.get('projected', {}).get('sources', []):
                            if 'configMap' in source:
                                cm_name = source.get('configMap', {}).get('name', '')
                                cm_id = self._find_node_id('ConfigMap', cm_name, namespace)
                                if cm_id:
                                    cve, cvss = self._get_best_cve_for_pod(pod_id)
                                    self._add_edge(pod_id, cm_id, 'reads', 2.0, cve=cve, cvss=cvss)
                                    count += 1

                # Env var configmaps
                for container in pod.get('spec', {}).get('containers', []):
                    for env_var in container.get('env', []):
                        cm_ref = env_var.get('valueFrom', {}).get('configMapKeyRef')
                        if cm_ref:
                            cm_name = cm_ref.get('name', '')
                            cm_id = self._find_node_id('ConfigMap', cm_name, namespace)
                            if cm_id:
                                cve, cvss = self._get_best_cve_for_pod(pod_id)
                                self._add_edge(pod_id, cm_id, 'reads', 2.0, cve=cve, cvss=cvss)
                                count += 1

                    for env_from in container.get('envFrom', []):
                        cm_ref = env_from.get('configMapRef')
                        if cm_ref:
                            cm_name = cm_ref.get('name', '')
                            cm_id = self._find_node_id('ConfigMap', cm_name, namespace)
                            if cm_id:
                                cve, cvss = self._get_best_cve_for_pod(pod_id)
                                self._add_edge(pod_id, cm_id, 'reads', 2.0, cve=cve, cvss=cvss)
                                count += 1
        print(f"  [OK] {count} edges")

    def _build_pod_node_edges(self):
        """Pod → Node (scheduled-on)"""
        print("[*] Building Pod → Node edges...")
        count = 0
        for namespace, pods in self._pods_by_ns.items():
            for pod in pods:
                pod_name = pod.get('metadata', {}).get('name', '')
                node_name = pod.get('spec', {}).get('nodeName', '')
                if not node_name:
                    continue

                pod_id = self._find_node_id('Pod', pod_name, namespace)
                node_id = self._find_node_id('Node', node_name, 'cluster')
                if pod_id and node_id:
                    cve, cvss = self._get_best_cve_for_pod(pod_id)
                    self._add_edge(pod_id, node_id, 'scheduled-on', 2.0, cve=cve, cvss=cvss)
                    count += 1
        print(f"  [OK] {count} edges")

    def _build_service_pod_edges(self):
        """Service → Pod (routes-to)"""
        print("[*] Building Service → Pod edges...")
        count = 0
        for namespace in self._services_by_ns:
            services = self._services_by_ns[namespace]
            pods = self._pods_by_ns.get(namespace, [])

            for svc in services:
                svc_name = svc.get('metadata', {}).get('name', '')
                selectors = svc.get('spec', {}).get('selector', {})
                if not selectors:
                    continue

                svc_id = self._find_node_id('Service', svc_name, namespace)
                if not svc_id:
                    continue

                for pod in pods:
                    pod_labels = pod.get('metadata', {}).get('labels', {})
                    pod_name = pod.get('metadata', {}).get('name', '')
                    if all(pod_labels.get(k) == v for k, v in selectors.items()):
                        pod_id = self._find_node_id('Pod', pod_name, namespace)
                        if pod_id:
                            cve, cvss = self._get_best_cve_for_pod(pod_id)
                            self._add_edge(svc_id, pod_id, 'routes-to', 3.0, cve=cve, cvss=cvss)
                            count += 1
        print(f"  [OK] {count} edges")

    def _build_deployment_pod_edges(self):
        """Deployment → Pod (creates)"""
        print("[*] Building Deployment → Pod edges...")
        count = 0
        for namespace in self._deployments_by_ns:
            deployments = self._deployments_by_ns[namespace]
            pods = self._pods_by_ns.get(namespace, [])

            for dep in deployments:
                dep_name = dep.get('metadata', {}).get('name', '')
                selectors = dep.get('spec', {}).get('selector', {}).get('matchLabels', {})
                if not selectors:
                    continue

                dep_id = self._find_node_id('Deployment', dep_name, namespace)
                if not dep_id:
                    continue

                for pod in pods:
                    pod_labels = pod.get('metadata', {}).get('labels', {})
                    pod_name = pod.get('metadata', {}).get('name', '')
                    if all(pod_labels.get(k) == v for k, v in selectors.items()):
                        pod_id = self._find_node_id('Pod', pod_name, namespace)
                        if pod_id:
                            cve, cvss = self._get_best_cve_for_pod(pod_id)
                            self._add_edge(dep_id, pod_id, 'creates', 2.0, cve=cve, cvss=cvss)
                            count += 1
        print(f"  [OK] {count} edges")

    def _build_rolebinding_edges(self):
        """ServiceAccount → Role (bound-to) via RoleBinding"""
        print("[*] Building SA → Role edges (via RoleBindings)...")
        count = 0
        for namespace, rbs in self._rolebindings_by_ns.items():
            for rb in rbs:
                rb_name = rb.get('metadata', {}).get('name', '')
                if is_system_resource(rb_name, namespace, 'RoleBinding'):
                    continue

                role_name = rb.get('roleRef', {}).get('name', '')
                role_kind = rb.get('roleRef', {}).get('kind', 'Role')

                for subject in rb.get('subjects', []):
                    if subject.get('kind') == 'ServiceAccount':
                        sa_name = subject.get('name', '')
                        sa_namespace = subject.get('namespace', namespace)

                        sa_id = self._find_node_id('ServiceAccount', sa_name, sa_namespace)
                        if role_kind == 'ClusterRole':
                            role_id = self._find_node_id('ClusterRole', role_name, 'cluster')
                        else:
                            role_id = self._find_node_id('Role', role_name, namespace)

                        if sa_id and role_id:
                            weight = 5.0
                            # Higher weight for dangerous roles
                            role_node = self.nodes.get(role_id, {})
                            if role_node.get('risk_score', 0) >= 8.0:
                                weight = 7.0
                            self._add_edge(sa_id, role_id, 'bound-to', weight)
                            count += 1
        print(f"  [OK] {count} edges")

    def _build_clusterrolebinding_edges(self):
        """ServiceAccount → ClusterRole (bound-to) via ClusterRoleBinding"""
        print("[*] Building SA → ClusterRole edges (via ClusterRoleBindings)...")
        count = 0
        for crb in getattr(self, '_clusterrolebindings', []):
            crb_name = crb.get('metadata', {}).get('name', '')
            if is_system_resource(crb_name, '', 'ClusterRoleBinding'):
                continue

            cr_name = crb.get('roleRef', {}).get('name', '')
            cr_id = self._find_node_id('ClusterRole', cr_name, 'cluster')
            if not cr_id:
                continue

            for subject in crb.get('subjects', []):
                if subject.get('kind') == 'ServiceAccount':
                    sa_name = subject.get('name', '')
                    sa_namespace = subject.get('namespace', 'default')
                    if is_system_resource(sa_name, sa_namespace, 'ServiceAccount'):
                        continue
                    sa_id = self._find_node_id('ServiceAccount', sa_name, sa_namespace)
                    if sa_id:
                        weight = 6.0
                        cr_node = self.nodes.get(cr_id, {})
                        if cr_node.get('risk_score', 0) >= 8.0:
                            weight = 8.0
                        self._add_edge(sa_id, cr_id, 'bound-to', weight)
                        count += 1
        print(f"  [OK] {count} edges")

    def _build_role_resource_edges(self):
        """Role/ClusterRole → Secret/ConfigMap (can-read / can-exec-on)"""
        print("[*] Building Role → Resource edges...")
        count = 0

        # Namespaced Roles
        for namespace, roles in self._roles_by_ns.items():
            for role in roles:
                role_name = role.get('metadata', {}).get('name', '')
                role_id = self._find_node_id('Role', role_name, namespace)
                if not role_id:
                    continue

                for rule in role.get('rules', []):
                    resources = rule.get('resources', [])
                    verbs = rule.get('verbs', [])

                    # Role → Secrets
                    if 'secrets' in resources and any(v in verbs for v in ['get', 'list']):
                        for secret in self._secrets_by_ns.get(namespace, []):
                            s_name = secret.get('metadata', {}).get('name', '')
                            s_id = self._find_node_id('Secret', s_name, namespace)
                            if s_id:
                                self._add_edge(role_id, s_id, 'can-read', 5.5)
                                count += 1

                    # Role → Pods (exec)
                    if 'pods/exec' in resources and any(v in verbs for v in ['get', 'create']):
                        for node in self.data.get('cluster_resources', {}).get(
                                'resources', {}).get('nodes', {}).get('items', []):
                            n_name = node.get('metadata', {}).get('name', '')
                            n_id = self._find_node_id('Node', n_name, 'cluster')
                            if n_id:
                                self._add_edge(role_id, n_id, 'can-exec-on', 7.0)
                                count += 1

                    # Role → ConfigMaps
                    if 'configmaps' in resources and any(v in verbs for v in ['get', 'list']):
                        for cm in self._configmaps_by_ns.get(namespace, []):
                            cm_name = cm.get('metadata', {}).get('name', '')
                            cm_id = self._find_node_id('ConfigMap', cm_name, namespace)
                            if cm_id:
                                self._add_edge(role_id, cm_id, 'can-read', 3.0)
                                count += 1

        # ClusterRoles
        cluster_data = self.data.get('cluster_resources', {})
        clusterroles = cluster_data.get('resources', {}).get('clusterroles', {}).get('items', [])
        for cr in clusterroles:
            cr_name = cr.get('metadata', {}).get('name', '')
            cr_id = self._find_node_id('ClusterRole', cr_name, 'cluster')
            if not cr_id:
                continue

            for rule in cr.get('rules', []):
                resources = rule.get('resources', [])
                verbs = rule.get('verbs', [])

                if 'secrets' in resources or '*' in resources:
                    if any(v in verbs for v in ['get', 'list', '*']):
                        # Link to all non-system secrets
                        for ns_secrets in self._secrets_by_ns.values():
                            for secret in ns_secrets:
                                s_name = secret.get('metadata', {}).get('name', '')
                                s_ns = secret.get('metadata', {}).get('namespace', '')
                                s_id = self._find_node_id('Secret', s_name, s_ns)
                                if s_id:
                                    self._add_edge(cr_id, s_id, 'can-read', 5.0)
                                    count += 1

                if 'namespaces' in resources or '*' in resources:
                    if any(v in verbs for v in ['get', 'list', '*']):
                        for nid, node in self.nodes.items():
                            if node['type'] == 'Namespace':
                                self._add_edge(cr_id, nid, 'admin-over', 6.0)
                                count += 1

        print(f"  [OK] {count} edges")

    # ─── Build All ────────────────────────────

    def build(self) -> Dict:
        """Build the complete cluster graph"""
        print("=" * 70)
        print("Kubernetes Cluster Graph Generator")
        print("=" * 70)
        print()

        # Phase 1: Build all nodes
        print("─── Phase 1: Building Nodes ───")
        print()
        self._build_namespace_nodes()
        self._build_node_nodes()
        self._build_pod_nodes()
        self._build_service_nodes()
        self._build_deployment_nodes()
        self._build_serviceaccount_nodes()
        self._build_secret_nodes()
        self._build_configmap_nodes()
        self._build_role_nodes()
        self._build_rolebinding_nodes()
        self._build_clusterrole_nodes()
        self._build_clusterrolebinding_data()
        self._build_networkpolicy_nodes()
        print()

        # Phase 2: Build all edges
        print("─── Phase 2: Building Edges ───")
        print()
        self._build_pod_sa_edges()
        self._build_pod_secret_edges()
        self._build_pod_configmap_edges()
        self._build_pod_node_edges()
        self._build_service_pod_edges()
        self._build_deployment_pod_edges()
        self._build_rolebinding_edges()
        self._build_clusterrolebinding_edges()
        self._build_role_resource_edges()
        print()

        # Build output
        cluster_name = self.data.get('metadata', {}).get('cluster_name', 'unknown-cluster')
        graph = {
            "metadata": {
                "cluster": cluster_name,
                "generated": datetime.now().strftime("%Y-%m-%d"),
                "node_count": len(self.nodes),
                "edge_count": len(self.edges),
                "description": "Auto-generated cluster graph from live Kubernetes data"
            },
            "nodes": list(self.nodes.values()),
            "edges": self.edges
        }

        return graph


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='Generate cluster graph (nodes + edges) from Kubernetes cluster data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python extract_relationships.py
  python extract_relationships.py --input k8s_resources/cluster.json --output cluster-graph.json
  python extract_relationships.py --nvd-api-key YOUR_KEY
        '''
    )

    parser.add_argument(
        '--input', '-i',
        default='k8s_resources/cluster.json',
        help='Path to cluster.json (default: k8s_resources/cluster.json)'
    )
    parser.add_argument(
        '--output', '-o',
        default='cluster-graph.json',
        help='Output file (default: cluster-graph.json)'
    )
    parser.add_argument(
        '--nvd-api-key',
        default=os.environ.get('NVD_API_KEY', ''),
        help='NVD API key for faster CVE lookups (default: $NVD_API_KEY env var)'
    )
    parser.add_argument(
        '--cache-dir',
        default=CACHE_DIR,
        help=f'Directory for NVD cache (default: {CACHE_DIR})'
    )

    args = parser.parse_args()

    # Resolve input path
    input_path = args.input
    if not os.path.isfile(input_path):
        # Try alternate locations
        alt_paths = [
            'cluster.json',
            'k8s_resources/cluster.json',
        ]
        for alt in alt_paths:
            if os.path.isfile(alt):
                input_path = alt
                break

    if not os.path.isfile(input_path):
        print(f"[FAIL] Input file not found: {args.input}")
        print(f"  Tried: {args.input}, cluster.json, k8s_resources/cluster.json")
        sys.exit(1)

    print(f"[*] Input:  {os.path.abspath(input_path)}")
    print(f"[*] Output: {os.path.abspath(args.output)}")
    print()

    # Load cluster data
    try:
        with open(input_path, 'r') as f:
            cluster_data = json.load(f)
    except Exception as e:
        print(f"[FAIL] Error loading {input_path}: {e}")
        sys.exit(1)

    # Initialize NVD components
    cache_manager = NVDCacheManager(args.cache_dir)
    api_key = args.nvd_api_key or None
    if api_key:
        print(f"[OK] Using NVD API key")
    else:
        print("[INFO] No NVD API key set. Rate limit: ~5 requests per 30 seconds.")
        print("       Set NVD_API_KEY env var or use --nvd-api-key for faster lookups.")
    print()

    cve_fetcher = CVEFetcher(cache_manager, api_key)

    # Build graph
    builder = ClusterGraphBuilder(cluster_data, cve_fetcher)
    graph = builder.build()

    # Write output
    try:
        with open(args.output, 'w') as f:
            json.dump(graph, f, indent=2)
        print(f"[OK] Cluster graph saved to: {args.output}")
    except Exception as e:
        print(f"[FAIL] Error saving output: {e}")
        sys.exit(1)

    # Summary
    print()
    print("=" * 70)
    print("[SUMMARY]")
    print(f"  • Cluster: {graph['metadata']['cluster']}")
    print(f"  • Nodes:   {graph['metadata']['node_count']}")
    print(f"  • Edges:   {graph['metadata']['edge_count']}")
    print()

    # Node type breakdown
    type_counts = defaultdict(int)
    for node in graph['nodes']:
        type_counts[node['type']] += 1
    print("  Node types:")
    for t, c in sorted(type_counts.items()):
        print(f"    {t}: {c}")

    # CVE summary
    pods_with_cves = sum(1 for n in graph['nodes'] if n['type'] == 'Pod' and n['cves'])
    total_cves = sum(len(n['cves']) for n in graph['nodes'] if n['type'] == 'Pod')
    edges_with_cves = sum(1 for e in graph['edges'] if e.get('cve'))
    print()
    print(f"  CVE coverage:")
    print(f"    Pods with CVEs: {pods_with_cves}")
    print(f"    Total CVE refs: {total_cves}")
    print(f"    Edges with CVEs: {edges_with_cves}")

    print()
    print("=" * 70)
    print("[OK] Done!")


if __name__ == "__main__":
    main()
