#!/bin/bash

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
NODES_FILE="nodes.txt"
DESIRED_KERNEL="6.8.0-64-generic"
IMAGE="ubuntu2404-baseline.ndz"
SSH_USER="root"
SSH_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=yes"
MAX_BOOT_RETRIES=5
BOOT_RETRY_SLEEP=30

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

# Join array elements with a delimiter
join_by() {
  local d=$1; shift
  echo "$*" | tr ' ' "$d"
}

# Convert full hostnames to short names for omf (node10-1.grid.orbit-lab.org -> node10-1)
to_short() { echo "$1" | cut -d'.' -f1; }

# Build comma-separated short names for omf -t flag
#omf_target() {
#  local nodes=("$@")
#  local short=()
#  for n in "${nodes[@]}"; do short+=( "$(to_short "$n")" ); done
#  join_by ',' "${short[@]}"
#}

omf_target() {
  local nodes=("$@")
  local short=()
  for n in "${nodes[@]}"; do short+=( "$(to_short "$n")" ); done
  # join with comma, no spaces
  local IFS=','
  echo "${short[*]}"
}

# ─────────────────────────────────────────────
# STEP 0: Load nodes
# ─────────────────────────────────────────────
mapfile -t ALL_NODES < "$NODES_FILE"
echo "Loaded ${#ALL_NODES[@]} nodes from $NODES_FILE"
echo ""

# ─────────────────────────────────────────────
# STEP 1: Check power status in one call
# ─────────────────────────────────────────────
echo "=== Checking power status ==="
ALL_TARGET=$(omf_target "${ALL_NODES[@]}")
echo "$ omf stat -t $ALL_TARGET"
stat_output=$(omf stat -t "$ALL_TARGET" 2>/dev/null)
echo "$stat_output"
echo ""

OFF_NODES=()
while IFS= read -r line; do
  if echo "$line" | grep -q "POWEROFF"; then
    # Extract short hostname from the line e.g. "   node10-10.grid.orbit-lab.org   POWEROFF"
    node=$(echo "$line" | grep -oP 'node[\w\-]+\.grid\.orbit-lab\.org')
    [[ -n "$node" ]] && OFF_NODES+=("$node")
  fi
done <<< "$stat_output"

echo "  Nodes POWEROFF : ${#OFF_NODES[@]}"
echo "  Nodes POWERON  : $(( ${#ALL_NODES[@]} - ${#OFF_NODES[@]} ))"
echo ""

# ─────────────────────────────────────────────
# STEP 2: Power on all OFF nodes at once
# ─────────────────────────────────────────────
if [[ ${#OFF_NODES[@]} -gt 0 ]]; then
  TARGET=$(omf_target "${OFF_NODES[@]}")
  echo ""
  echo "=== Powering on ${#OFF_NODES[@]} nodes ==="
  echo "$ omf tell -t $TARGET -a on"
  omf tell -t "$TARGET" -a on
else
  echo "All nodes already powered on."
fi
echo ""

# ─────────────────────────────────────────────
# STEP 3: Retry SSH uname -r until nodes are up
# ─────────────────────────────────────────────
echo "=== Waiting for nodes to boot and checking kernel ==="

declare -A KERNEL_RESULT   # node -> kernel string or "FAILED"
NODES_UP=()
BOOT_FAILED=()

for node in "${ALL_NODES[@]}"; do
  success=0
  for ((i=1; i<=MAX_BOOT_RETRIES; i++)); do
    kernel=$(ssh $SSH_OPTS "${SSH_USER}@${node}" "uname -r" 2>/dev/null)
    if [[ -n "$kernel" ]]; then
      KERNEL_RESULT["$node"]="$kernel"
      NODES_UP+=("$node")
      success=1
      echo "  [$node] Kernel: $kernel (attempt $i)"
      break
    fi
    echo "  [$node] SSH failed, retry $i/$MAX_BOOT_RETRIES (sleeping ${BOOT_RETRY_SLEEP}s)..."
    sleep "$BOOT_RETRY_SLEEP"
  done

  if [[ $success -eq 0 ]]; then
    KERNEL_RESULT["$node"]="FAILED"
    BOOT_FAILED+=("$node")
  fi
done

if [[ ${#BOOT_FAILED[@]} -gt 0 ]]; then
  echo ""
  echo "  WARNING: ${#BOOT_FAILED[@]} node(s) never responded over SSH — skipping:"
  for n in "${BOOT_FAILED[@]}"; do echo "    - $n"; done
fi
echo ""

# ─────────────────────────────────────────────
# STEP 4: Identify nodes needing imaging, shut them off
# ─────────────────────────────────────────────
echo "=== Checking kernel versions ==="
NEEDS_IMAGE=()
for node in "${NODES_UP[@]}"; do
  if [[ "${KERNEL_RESULT[$node]}" != "$DESIRED_KERNEL" ]]; then
    NEEDS_IMAGE+=("$node")
    echo "  [$node] Wrong kernel (${KERNEL_RESULT[$node]}) — needs imaging"
  else
    echo "  [$node] Kernel OK — skipping"
  fi
done
echo ""

if [[ ${#NEEDS_IMAGE[@]} -eq 0 ]]; then
  echo "All reachable nodes have the correct kernel. Nothing to image."
else
  TARGET=$(omf_target "${NEEDS_IMAGE[@]}")
  echo "=== Shutting off ${#NEEDS_IMAGE[@]} nodes before imaging ==="
  echo "$ omf tell -t $TARGET -a offh"
  omf tell -t "$TARGET" -a offh
  echo ""

  # ─────────────────────────────────────────────
  # STEP 5: Image all nodes in one parallel omf load
  # ─────────────────────────────────────────────
  echo "=== Imaging ${#NEEDS_IMAGE[@]} nodes with $IMAGE ==="
  echo "$ omf load -t $TARGET -i $IMAGE"
  echo ""
  omf_output=$(omf load -t "$TARGET" -i "$IMAGE" 2>&1)
  echo "$omf_output"
  echo ""

  # Parse which nodes imaged successfully from omf output
  IMAGED_OK=()
  IMAGED_FAIL=()
  for node in "${NEEDS_IMAGE[@]}"; do
    short=$(to_short "$node")
    # omf load prints node names in the success summary
    if echo "$omf_output" | grep -q "$short"; then
      IMAGED_OK+=("$node")
    else
      IMAGED_FAIL+=("$node")
    fi
  done

  if [[ ${#IMAGED_FAIL[@]} -gt 0 ]]; then
    echo "  WARNING: ${#IMAGED_FAIL[@]} node(s) failed imaging — skipping:"
    for n in "${IMAGED_FAIL[@]}"; do echo "    - $n"; done
  fi
  echo ""

  # ─────────────────────────────────────────────
  # STEP 6: Power on imaged nodes, verify kernel
  # ─────────────────────────────────────────────
  if [[ ${#IMAGED_OK[@]} -gt 0 ]]; then
    TARGET_OK=$(omf_target "${IMAGED_OK[@]}")
    echo "=== Powering on ${#IMAGED_OK[@]} freshly imaged nodes ==="
    echo "$ omf tell -t $TARGET_OK -a on"
    omf tell -t "$TARGET_OK" -a on
    echo ""

    echo "=== Verifying kernel on imaged nodes ==="
    VERIFY_FAIL=()
    for node in "${IMAGED_OK[@]}"; do
      success=0
      for ((i=1; i<=MAX_BOOT_RETRIES; i++)); do
        kernel=$(ssh $SSH_OPTS "${SSH_USER}@${node}" "uname -r" 2>/dev/null)
        if [[ -n "$kernel" ]]; then
          if [[ "$kernel" == "$DESIRED_KERNEL" ]]; then
            echo "  [$node] Kernel OK ($kernel)"
          else
            echo "  [$node] WRONG kernel after imaging: $kernel (expected $DESIRED_KERNEL)"
            VERIFY_FAIL+=("$node")
          fi
          success=1
          break
        fi
        echo "  [$node] SSH not ready, retry $i/$MAX_BOOT_RETRIES..."
        sleep "$BOOT_RETRY_SLEEP"
      done
      if [[ $success -eq 0 ]]; then
        echo "  [$node] Never came back up after imaging"
        VERIFY_FAIL+=("$node")
      fi
    done

    if [[ ${#VERIFY_FAIL[@]} -gt 0 ]]; then
      echo ""
      echo "  WARNING: ${#VERIFY_FAIL[@]} node(s) failed post-image kernel check:"
      for n in "${VERIFY_FAIL[@]}"; do echo "    - $n"; done
    fi
  fi
fi

# ─────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────
echo ""
echo "============================================"
echo " INIT COMPLETE — SUMMARY"
echo "============================================"
echo "  Total nodes      : ${#ALL_NODES[@]}"
echo "  Boot failures    : ${#BOOT_FAILED[@]}"
echo "  Already OK       : $(( ${#NODES_UP[@]} - ${#NEEDS_IMAGE[@]} ))"
echo "  Imaged           : ${#IMAGED_OK[@]:-0}"
echo "  Post-image fails : ${#VERIFY_FAIL[@]:-0}"
echo "============================================"
