@echo off

echo ==^> Creating kind cluster...
kind create cluster --config cluster.yml || exit /b

echo ==^> Waiting for cluster to be ready...
kubectl wait --for=condition=Ready nodes --all --timeout=60s || exit /b

echo ==^> Applying namespaces...
kubectl apply -f namespace.yml || exit /b

echo ==^> Applying service accounts...
kubectl apply -f serviceAccount.yml || exit /b

echo ==^> Applying secrets...
kubectl apply -f secrets.yml || exit /b

echo ==^> Applying configmaps...
kubectl apply -f configMap.yml || exit /b

echo ==^> Applying roles...
kubectl apply -f role.yml || exit /b

echo ==^> Applying rolebindings..

echo ==^> Applying clusterroles...
kubectl apply -f clusterRole.yml || exit /b

echo ==^> Applying clusterrolebindings...
kubectl apply -f clusterRolebinding.yml || exit /b

echo ==^> Applying deployments...
kubectl apply -f deployment.yml || exit /b

echo ==^> Applying services...
kubectl apply -f service.yml || exit /b

echo.
echo ==^> Cluster ready! Verify with:
echo     kubectl get pods -A
echo     kubectl get svc -A
