#!/bin/bash

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
NODES_FILE="nodes.txt"
DESIRED_KERNEL="6.8.0-64-generic"
IMAGE="himan-ubuntu2404-ddos.ndz"
SSH_USER="root"
SSH_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=yes"
MAX_BOOT_RETRIES=5
BOOT_RETRY_SLEEP=30

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

# Convert full hostname to short name for omf
# node10-1.grid.orbit-lab.org -> node10-1
to_short() { echo "$1" | cut -d'.' -f1; }

# Build comma-separated short names for omf -t flag
omf_target() {
  local nodes=("$@")
  local short=()
  for n in "${nodes[@]}"; do short+=( "$(to_short "$n")" ); done
  local IFS=','
  echo "${short[*]}"
}

# ─────────────────────────────────────────────
# STEP 0: Load nodes from nodes.txt (first column only)
# ─────────────────────────────────────────────
mapfile -t ALL_NODES < <(awk '{print $1}' "$NODES_FILE")
echo "Loaded ${#ALL_NODES[@]} nodes from $NODES_FILE"
echo ""

ALL_TARGET=$(omf_target "${ALL_NODES[@]}")

# ─────────────────────────────────────────────
# STEP 1: Power off all nodes
# ─────────────────────────────────────────────
echo "=== Powering off all nodes ==="
echo "$ omf tell -t $ALL_TARGET -a offh"
omf tell -t "$ALL_TARGET" -a offh
echo ""

# ─────────────────────────────────────────────
# STEP 2: Image all nodes in one parallel omf load
# ─────────────────────────────────────────────
echo "=== Imaging ${#ALL_NODES[@]} nodes with $IMAGE ==="
echo "$ omf load -t $ALL_TARGET -i $IMAGE"
echo ""
omf_output=$(omf load -t "$ALL_TARGET" -i "$IMAGE" 2>&1)
echo "$omf_output"
echo ""

# Parse which nodes imaged successfully from omf output
IMAGED_OK=()
IMAGED_FAIL=()

# omf load reports total success count in the summary line
success_count=$(echo "$omf_output" | grep -oP '^\s*\K[0-9]+(?= nodes? successfully imaged)')

if [[ -n "$success_count" && "$success_count" -eq "${#ALL_NODES[@]}" ]]; then
  # All nodes succeeded
  IMAGED_OK=("${ALL_NODES[@]}")
elif [[ -n "$success_count" && "$success_count" -gt 0 ]]; then
  # Partial success — check the topology file for which ones succeeded
  topo_file=$(echo "$omf_output" | grep -oP "'/tmp/omf-load[^']+success\.rb'" | tr -d "'")
  if [[ -f "$topo_file" ]]; then
    for node in "${ALL_NODES[@]}"; do
      short=$(to_short "$node")
      if grep -q "$short" "$topo_file"; then
        IMAGED_OK+=("$node")
      else
        IMAGED_FAIL+=("$node")
        echo "  WARNING: [$node] not in success topology — skipping"
      fi
    done
  else
    # No topology file accessible — fall back to trusting the count
    echo "  WARNING: Cannot read topology file, assuming first $success_count nodes succeeded"
    IMAGED_OK=("${ALL_NODES[@]:0:$success_count}")
    IMAGED_FAIL=("${ALL_NODES[@]:$success_count}")
  fi
else
  # No success line found — all failed
  IMAGED_FAIL=("${ALL_NODES[@]}")
  echo "  ERROR: No nodes successfully imaged"
fi

if [[ -f "$topo_file" ]]; then
    # Extract comma-separated node list from defTopology('...', 'node1,node2,...')
    topo_nodes=$(grep -oP "defTopology\('[^']+',\s*'\K[^']+" "$topo_file")

    for node in "${ALL_NODES[@]}"; do
      if echo "$topo_nodes" | tr ',' '\n' | grep -qx "$node"; then
        IMAGED_OK+=("$node")
      else
        IMAGED_FAIL+=("$node")
        echo "  WARNING: [$node] not in success topology — skipping"
      fi
    done
fi

if [[ ${#IMAGED_OK[@]} -eq 0 ]]; then
  echo "ERROR: No nodes imaged successfully. Exiting."
  exit 1
fi

# ─────────────────────────────────────────────
# STEP 3: Power on successfully imaged nodes
# ─────────────────────────────────────────────
TARGET_OK=$(omf_target "${IMAGED_OK[@]}")
echo "=== Powering on ${#IMAGED_OK[@]} imaged nodes ==="
echo "$ omf tell -t $TARGET_OK -a on"
omf tell -t "$TARGET_OK" -a on
echo ""

# ─────────────────────────────────────────────
# STEP 4: Wait for nodes to boot, verify kernel
# All nodes attempted each round before sleeping
# ─────────────────────────────────────────────
echo "=== Waiting for nodes to boot and verifying kernel ==="

NODES_OK=()
VERIFY_FAIL=()
PENDING=("${IMAGED_OK[@]}")

for ((i=1; i<=MAX_BOOT_RETRIES; i++)); do
  STILL_PENDING=()

  for node in "${PENDING[@]}"; do
    kernel=$(ssh $SSH_OPTS "${SSH_USER}@${node}" "uname -r" 2>/dev/null)
    if [[ -n "$kernel" ]]; then
      if [[ "$kernel" == "$DESIRED_KERNEL" ]]; then
        echo "  [$node] Kernel OK ($kernel) (attempt $i)"
        NODES_OK+=("$node")
      else
        echo "  [$node] WRONG kernel: $kernel (expected $DESIRED_KERNEL)"
        VERIFY_FAIL+=("$node")
      fi
    else
      STILL_PENDING+=("$node")
    fi
  done

  PENDING=("${STILL_PENDING[@]}")

  if [[ ${#PENDING[@]} -eq 0 ]]; then
    break
  fi

  if [[ $i -lt $MAX_BOOT_RETRIES ]]; then
    echo ""
    echo "  ${#PENDING[@]} node(s) not yet up, sleeping ${BOOT_RETRY_SLEEP}s before retry $((i+1))/$MAX_BOOT_RETRIES..."
    sleep "$BOOT_RETRY_SLEEP"
  fi
done

# Nodes still pending after all retries have failed
for node in "${PENDING[@]}"; do
  echo "  [$node] Never came back up after $MAX_BOOT_RETRIES attempts"
  VERIFY_FAIL+=("$node")
done

# ─────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────
echo ""
echo "============================================"
echo " INIT COMPLETE — SUMMARY"
echo "============================================"
echo "  Total nodes      : ${#ALL_NODES[@]}"
echo "  Imaging failed   : ${#IMAGED_FAIL[@]}"
echo "  Kernel OK        : ${#NODES_OK[@]}"
echo "  Kernel failures  : ${#VERIFY_FAIL[@]}"
echo ""
if [[ ${#NODES_OK[@]} -gt 0 ]]; then
  echo "  Successful nodes :"
  for n in "${NODES_OK[@]}"; do echo "    ✓ $n"; done
fi
if [[ ${#VERIFY_FAIL[@]} -gt 0 ]]; then
  echo ""
  echo "  Failed nodes :"
  for n in "${VERIFY_FAIL[@]}"; do echo "    ✗ $n"; done
fi
echo "============================================"
