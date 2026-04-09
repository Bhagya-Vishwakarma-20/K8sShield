
"""
Kubernetes Resource Collector
This script collects all Kubernetes resources from all namespaces
and combines them into a single JSON file.
Namespaces are fetched directly from the live Kubernetes cluster.
Works with any Kubernetes cluster connected via kubectl.
"""

import json
import subprocess
import os
import sys
import argparse
from pathlib import Path
from datetime import datetime


OUTPUT_DIR = "k8s_resources"
COMBINED_OUTPUT = "cluster.json"


NAMESPACED_RESOURCES = [
    "pods",
    "services",
    "deployments",
    "roles",
    "rolebindings",
    "serviceaccounts",
    "secrets",
    "configmaps",
    "networkpolicies",
]


CLUSTER_RESOURCES = [
    "clusterroles",
    "clusterrolebindings",
    "nodes",
]

def create_output_directory():
    """Create output directory if it doesn't exist"""
    Path(OUTPUT_DIR).mkdir(exist_ok=True)
    print(f"[OK] Output directory: {OUTPUT_DIR}")

def check_kubectl_connectivity():
    """Check if kubectl is connected to a cluster"""
    try:
        result = subprocess.run(
            "kubectl cluster-info",
            shell=True,
            capture_output=True,
            text=True,
            check=True,
            timeout=5
        )
        return True, None
    except subprocess.CalledProcessError as e:
        return False, e.stderr
    except subprocess.TimeoutExpired:
        return False, "kubectl command timed out"
    except Exception as e:
        return False, str(e)

def get_cluster_name():
    """Get the current cluster name from kubectl context"""
    try:
        result = subprocess.run(
            "kubectl config current-context",
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        context = result.stdout.strip()
        
        return context if context else "unknown-cluster"
    except:
        return "unknown-cluster"

def get_raw_namespaces_from_cluster():
    """Get namespaces directly from the cluster"""
    try:
        cmd = "kubectl get namespaces -o json"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        data = json.loads(result.stdout)
        namespaces = [ns['metadata']['name'] for ns in data.get('items', [])]
        return namespaces
    except Exception as e:
        print(f"[FAIL] Error fetching namespaces from cluster: {e}")
        return []

def get_namespaces():
    """Get namespaces directly from the live Kubernetes cluster"""
    print("[*] Fetching namespaces from cluster...")
    namespaces = get_raw_namespaces_from_cluster()
    if namespaces:
        print(f"[OK] Found {len(namespaces)} namespaces in cluster")
    return namespaces

def run_kubectl_command(cmd):
    """Execute kubectl command and return JSON output"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"[FAIL] Command failed: {cmd}")
        print(f"  Error: {e.stderr}")
        return None
    except json.JSONDecodeError as e:
        print(f"[FAIL] Failed to parse JSON from command: {cmd}")
        print(f"  Error: {e}")
        return None

def collect_namespaced_resources(namespace):
    """Collect all namespaced resources from a given namespace"""
    namespace_data = {
        "namespace": namespace,
        "resources": {}
    }
    
    for resource_type in NAMESPACED_RESOURCES:
        cmd = f"kubectl get {resource_type} -n {namespace} -o json"
        print(f"  → {resource_type}...", end="", flush=True)
        
        data = run_kubectl_command(cmd)
        if data:
            namespace_data["resources"][resource_type] = data
            item_count = len(data.get('items', []))
            print(f" [OK] ({item_count} items)")
        else:
            namespace_data["resources"][resource_type] = {"items": []}
            print(" [SKIP] (skipped)")
    
    return namespace_data

def collect_cluster_resources():
    """Collect cluster-level resources"""
    cluster_data = {
        "scope": "cluster",
        "resources": {}
    }
    
    for resource_type in CLUSTER_RESOURCES:
        cmd = f"kubectl get {resource_type} -o json"
        print(f"  → {resource_type}...", end="", flush=True)
        
        data = run_kubectl_command(cmd)
        if data:
            cluster_data["resources"][resource_type] = data
            item_count = len(data.get('items', []))
            print(f" [OK] ({item_count} items)")
        else:
            cluster_data["resources"][resource_type] = {"items": []}
            print(" [SKIP] (skipped)")
    
    return cluster_data

def save_json_file(data, filename):
    """Save data to JSON file"""
    filepath = os.path.join(OUTPUT_DIR, filename)
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return filepath
    except Exception as e:
        print(f"[FAIL] Error saving {filepath}: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description='Collect and combine all Kubernetes resources from any cluster connected via kubectl',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python collect_all_resources.py
  python collect_all_resources.py --output my_resources
        '''
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='k8s_resources',
        help='Output directory (default: k8s_resources)'
    )
    parser.add_argument(
        '--include-cluster-resources',
        action='store_true',
        default=True,
        help='Include cluster-level resources like clusterroles (default: True)'
    )
    
    args = parser.parse_args()
    
    global OUTPUT_DIR
    OUTPUT_DIR = args.output
    
    print("=" * 70)
    print("Kubernetes Resource Collector - Universal")
    print("=" * 70)
    print()
    
    
    create_output_directory()
    print()
    
    
    print("[*] Checking kubectl connectivity...")
    connected, error = check_kubectl_connectivity()
    if not connected:
        print(f"[FAIL] Not connected to a Kubernetes cluster!")
        print(f"  Error: {error}")
        print()
        print("Please ensure:")
        print("  1. kubectl is installed")
        print("  2. kubeconfig is configured (~/.kube/config)")
        print("  3. A cluster is running and accessible")
        sys.exit(1)
    
    cluster_name = get_cluster_name()
    print(f"[OK] Connected to cluster: {cluster_name}")
    print()
    
    
    namespaces = get_namespaces()
    if not namespaces:
        print("[FAIL] No namespaces found!")
        sys.exit(1)
    
    print(f"[OK] Found {len(namespaces)} namespaces: {', '.join(namespaces)}")
    print()
    
    
    all_data = {
        "metadata": {
            "collected_at": datetime.now().isoformat(),
            "cluster_name": cluster_name,
            "namespaces": namespaces,
            "resource_types": {
                "namespaced": NAMESPACED_RESOURCES,
                "cluster": CLUSTER_RESOURCES if args.include_cluster_resources else []
            }
        },
        "namespaced_resources": [],
        "cluster_resources": []
    }
    
    
    if args.include_cluster_resources:
        print("[*] Collecting cluster-level resources...")
        cluster_data = collect_cluster_resources()
        all_data["cluster_resources"] = cluster_data
        cluster_file = save_json_file(cluster_data, "cluster_resources.json")
        print(f"[OK] Saved to: {cluster_file}")
        print()
    
    
    print("[*] Collecting resources from namespaces...")
    for namespace in namespaces:
        print(f"\n[*] Namespace: {namespace}")
        ns_data = collect_namespaced_resources(namespace)
        all_data["namespaced_resources"].append(ns_data)
        
        
        filename = f"{namespace}_resources.json"
        filepath = save_json_file(ns_data, filename)
        print(f"[OK] Saved to: {filepath}")
    
    print()
    print("=" * 70)
    print("[*] Combining all resources into single JSON file...")
    print("=" * 70)
    
    
    combined_path = save_json_file(all_data, COMBINED_OUTPUT)
    print(f"[OK] Combined file saved to: {combined_path}")
    print()
    
    
    print("[SUMMARY] Summary:")
    print(f"  • Cluster: {cluster_name}")
    print(f"  • Total namespaces: {len(namespaces)}")
    print(f"  • Namespaced resource types: {len(NAMESPACED_RESOURCES)}")
    print(f"  • Cluster resource types: {len(CLUSTER_RESOURCES) if args.include_cluster_resources else 0}")
    print(f"  • Individual files created: {len(namespaces) + (1 if args.include_cluster_resources else 0)}")
    print(f"  • Combined file: {COMBINED_OUTPUT}")
    print()
    
    
    print("[FILES] Generated files:")
    for file in sorted(os.listdir(OUTPUT_DIR)):
        filepath = os.path.join(OUTPUT_DIR, file)
        size = os.path.getsize(filepath)
        print(f"  • {file} ({size:,} bytes)")
    
    print()
    print("[OK] Done!")
    print()
    print("[INFO] Tip: The combined file contains all resources and is ready for import,")
    print("   analysis, or further processing!")

if __name__ == "__main__":
    main()
