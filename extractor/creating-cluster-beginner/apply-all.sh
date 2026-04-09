#!/bin/bash
set -e

echo "==> Creating beginner kind cluster..."
kind create cluster --config cluster.yml

echo "==> Waiting for cluster nodes to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=60s

echo "==> Applying ConfigMap..."
kubectl apply -f configMap.yml

echo "==> Applying Deployments..."
kubectl apply -f deployment.yml

echo "==> Applying Services..."
kubectl apply -f service.yml

echo "==> Applying Role..."
kubectl apply -f role.yml

echo "==> Applying RoleBinding..."
kubectl apply -f rolebinding.yml

echo "==> Setup complete! Use 'kubectl get all' to see your resources."
