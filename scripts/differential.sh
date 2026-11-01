#!/usr/bin/env bash
# Compares netpolwarden with a real NetworkPolicy implementation. Creates a kind cluster with
# Calico, applies testdata/differential/cluster.yaml, tries every pod -> pod connection on every
# declared port with agnhost, and requires netpolwarden --can to give the same answer for each.
# Needs docker, kind and kubectl; CI has them.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=${NETPOLWARDEN:-./bin/netpolwarden}
CALICO=v3.28.2
FIXTURE=testdata/differential/cluster.yaml
CLUSTER=netpolwarden

if ! kind get clusters | grep -qx "$CLUSTER"; then
  cat <<EOF | kind create cluster --name "$CLUSTER" --config -
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF
  kubectl apply -f "https://raw.githubusercontent.com/projectcalico/calico/$CALICO/manifests/calico.yaml" > /dev/null
fi
kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s
kubectl apply -f "$FIXTURE" > /dev/null
kubectl wait --for=condition=Ready pod --all -n np-x --timeout=300s
kubectl wait --for=condition=Ready pod --all -n np-y --timeout=300s
sleep 10 # let Calico program the policies just applied

pods=$(kubectl get pods -n np-x -o name | sed 's|pod/|np-x/|'; kubectl get pods -n np-y -o name | sed 's|pod/|np-y/|')
agree=0 differ=0
for src in $pods; do
  for dst in $pods; do
    [ "$src" = "$dst" ] && continue
    ip=$(kubectl get pod -n "${dst%%/*}" "${dst#*/}" -o jsonpath='{.status.podIP}')
    for port in $(kubectl get pod -n "${dst%%/*}" "${dst#*/}" -o jsonpath='{.spec.containers[*].ports[*].containerPort}'); do
      if kubectl exec -n "${src%%/*}" "${src#*/}" -- /agnhost connect "$ip:$port" --timeout=3s --protocol=tcp > /dev/null 2>&1; then
        real=allowed
      else
        real=denied
      fi
      if "$BIN" "$FIXTURE" --can "$src $dst $port" > /dev/null; then predicted=allowed; else predicted=denied; fi
      if [ "$real" = "$predicted" ]; then
        agree=$((agree + 1))
      else
        differ=$((differ + 1))
        echo "DIFFER  $src -> $dst:$port  cluster: $real  netpolwarden: $predicted"
        "$BIN" "$FIXTURE" --can "$src $dst $port" | sed 's/^/        /' || true
      fi
    done
  done
done
echo "$agree connections agree, $differ differ (Calico $CALICO)"
[ "$differ" -eq 0 ]
