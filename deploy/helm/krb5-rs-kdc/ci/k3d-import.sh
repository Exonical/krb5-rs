#!/usr/bin/env bash
# Usage: k3d-import.sh CLUSTER IMAGE...
set -euo pipefail

cluster=$1
shift
node="k3d-${cluster}-server-0"

full_ref() {
  local first=${1%%/*}
  if [[ $1 != */* ]]; then
    echo "docker.io/library/$1"
  elif [[ $first == *.* || $first == *:* || $first == localhost ]]; then
    echo "$1"
  else
    echo "docker.io/$1"
  fi
}

for image in "$@"; do
  if [[ $image == *@* ]]; then
    k3d image import "$image" -c "$cluster" || true
    continue
  fi
  want=$(full_ref "$image")
  for attempt in 1 2 3; do
    k3d image import "$image" -c "$cluster"
    if docker exec "$node" ctr -n k8s.io images ls -q | grep -qxF "$want"; then
      continue 2
    fi
    echo "k3d-import: $want missing from $node after attempt $attempt" >&2
  done
  exit 1
done
