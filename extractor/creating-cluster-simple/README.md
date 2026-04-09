# Simplified Kubernetes Cluster

A minimal cluster setup with fewer pods and less complexity, designed for quick testing.

## What's Different from `creating-cluster/`

| Resource             | Original | Simplified |
|----------------------|----------|------------|
| Kind nodes           | 4        | 2          |
| Namespaces           | 5        | 2          |
| Deployments (pods)   | 7        | 2          |
| Services             | 5        | 2          |
| Service Accounts     | 7        | 2          |
| Secrets              | 4        | 1          |
| ConfigMaps           | 3        | 1          |
| Roles                | 6        | 1          |
| RoleBindings         | 7        | 1          |
| ClusterRoles         | 2        | 1          |
| ClusterRoleBindings  | 1        | 1          |

## Architecture

```
[app namespace]                    [data namespace]
  web-app (nginx:1.21)    ──────►   production-db (postgres:13)
  sa-web                            sa-db
  web-svc (LoadBalancer)            postgres-svc (ClusterIP)
                                    secret-db-credentials
```

**Attack path:** `sa-web` (app ns) → `role-secret-reader` (data ns) → reads `secret-db-credentials`

## Quick Start

```bash
cd creating-cluster-simple
bash apply-all.sh
```

## Teardown

```bash
kind delete cluster --name k8s-simple-lab
```
