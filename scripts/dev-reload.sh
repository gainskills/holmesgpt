#!/usr/bin/env bash
set -euo pipefail

# Rebuild, load into cluster nodes, and redeploy Holmes & Holmes Operator locally.
# Usage: ./scripts/dev-reload.sh [kind-cluster-name]

KIND_CLUSTER="${1:-kind}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> 1. Building Holmes API Docker image..."
docker build -t robustadev/holmes:dev .

echo "==> 2. Building Holmes Operator Docker image..."
docker build -f Dockerfile.operator -t robustadev/holmes-operator:dev .

echo "==> 3. Loading images into Kubernetes nodes..."
if command -v kind >/dev/null 2>&1; then
    echo "Using 'kind load'..."
    kind load docker-image robustadev/holmes:dev --name "${KIND_CLUSTER}" || true
    kind load docker-image robustadev/holmes-operator:dev --name "${KIND_CLUSTER}" || true
else
    # Fallback: import directly into all detected worker/node containers
    NODES=$(docker ps --format '{{.Names}}' | grep -E 'worker|control-plane' || true)
    if [ -z "$NODES" ]; then
        # Check network inspect if docker ps is filtered
        NODES="desktop-worker desktop-worker2 desktop-worker3"
    fi
    for node in $NODES; do
        if docker inspect "$node" >/dev/null 2>&1; then
            echo "Importing images into node container: $node..."
            docker save robustadev/holmes:dev | docker exec -i "$node" ctr -n k8s.io images import -
            docker save robustadev/holmes-operator:dev | docker exec -i "$node" ctr -n k8s.io images import -
        fi
    done
fi

echo "==> 4. Applying Operator CRDs..."
kubectl apply -f helm/holmes/crds/

echo "==> 5. Deploying via Helm..."
VALUES_ARGS=()
if [ -f "helm/holmes/values-dev.yaml" ]; then
    VALUES_ARGS+=("-f" "helm/holmes/values-dev.yaml")
fi
if [ -f "helm/holmes/values-local.yaml" ]; then
    echo "Found helm/holmes/values-local.yaml (loading local overrides/secrets)"
    VALUES_ARGS+=("-f" "helm/holmes/values-local.yaml")
fi

if [ ${#VALUES_ARGS[@]} -eq 0 ]; then
    echo "Warning: No custom values file found. Deploying with default values."
fi

helm upgrade --install holmes ./helm/holmes "${VALUES_ARGS[@]}"

echo "==> 6. Restarting deployments to ensure new images are picked up..."
kubectl rollout restart deployment/holmes-holmes 2>/dev/null || true
kubectl rollout restart deployment/holmes-operator 2>/dev/null || true

echo "==> 7. Waiting for deployment rollout..."
kubectl rollout status deployment/holmes-holmes --timeout=120s || true
kubectl rollout status deployment/holmes-operator --timeout=120s || true

echo ""
echo "Deployment successfully updated and running!"
echo "To test Holmes API:"
echo "  kubectl port-forward svc/holmes-holmes 5050:80"
echo "  curl http://localhost:5050/healthz"
