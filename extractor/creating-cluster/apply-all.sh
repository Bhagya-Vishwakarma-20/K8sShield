
#!/bin/bash
set -e

echo "==> Creating kind cluster..."
kind create cluster --config cluster.yml

echo "==> Waiting for cluster to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=60s

echo "==> Applying namespaces..."
kubectl apply -f namespace.yml

echo "==> Applying service accounts..."
kubectl apply -f serviceAccount.yml

echo "==> Applying secrets..."
kubectl apply -f secrets.yml

echo "==> Applying configmaps..."
kubectl apply -f configMap.yml

echo "==> Applying roles..."
kubectl apply -f role.yml

echo "==> Applying rolebindings..."
kubectl apply -f rolebinding.yml

echo "==> Applying clusterroles..."
kubectl apply -f clusterRole.yml

echo "==> Applying clusterrolebindings..."
kubectl apply -f clusterRolebinding.yml

echo "==> Applying deployments..."
kubectl apply -f deployment.yml

echo "==> Applying services..."
kubectl apply -f service.yml

echo ""
echo "==> Cluster ready. Verify with:"
echo "    kubectl get pods -A"
echo "    kubectl get rolebindings -A"
echo "    kubectl get clusterrolebindings"