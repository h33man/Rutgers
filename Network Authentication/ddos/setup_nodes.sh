#!/bin/bash

NODES_FILE="nodes.txt"
SSH_USER="root"
SSH_PASS=""
UDP_CLIENT_LOCAL="./udp_client"
UDP_CLIENT_REMOTE="/usr/local/bin/udp_client"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"
CONTROL_NODE_IP="10.29.1.4"
DATA_IFACE="DATA1"
DATA_MTU=9000

# sshpass is required for password-based key copying
#if ! command -v sshpass &>/dev/null; then
#  echo "Installing sshpass..."
#  apt-get install -y sshpass
#fi

# Generate key if it doesn't exist
#if [[ ! -f ~/.ssh/id_rsa ]]; then
#  echo "Generating SSH key pair..."
#  ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
#fi

# Load nodes and IPs from nodes.txt
declare -A NODE_IP   # node -> data plane IP
while IFS=' ' read -r node ip; do
  NODE_IP["$node"]="$ip"
done < "$NODES_FILE"
ALL_NODES=("${!NODE_IP[@]}")
echo "Loaded ${#ALL_NODES[@]} nodes from $NODES_FILE"

# STEP 1: Copy SSH keys to all nodes in parallel
#echo ""
#echo "=== Copying SSH public key to all nodes ==="
#for node in "${ALL_NODES[@]}"; do
#  sshpass -p "$SSH_PASS" ssh-copy-id \
#    -i ~/.ssh/id_rsa.pub \
#    -o StrictHostKeyChecking=no \
#    -o ConnectTimeout=10 \
#    "${SSH_USER}@${node}" &
#done
#wait

# STEP 2: Verify SSH key access
echo ""
echo "=== Verifying key-based SSH access ==="
SSH_FAIL=()
for node in "${ALL_NODES[@]}"; do
  if ssh -o BatchMode=yes $SSH_OPTS "${SSH_USER}@${node}" "echo ok" &>/dev/null; then
    echo "  [$node] SSH OK"
  else
    echo "  [$node] SSH FAILED"
    SSH_FAIL+=("$node")
  fi
done

if [[ ${#SSH_FAIL[@]} -gt 0 ]]; then
  echo ""
  echo "WARNING: ${#SSH_FAIL[@]} node(s) failed SSH — skipping:"
  for n in "${SSH_FAIL[@]}"; do echo "  - $n"; done
fi

# STEP 3: Configure data plane interface if needed
for node in "${ALL_NODES[@]}"; do
  if printf '%s\n' "${SSH_FAIL[@]}" | grep -qx "$node"; then
    continue
  fi

  client_ip="${NODE_IP[$node]}"

  ssh -o BatchMode=yes $SSH_OPTS "${SSH_USER}@${node}" bash << EOF &
    # Already reachable — nothing to do
    if ping -c1 -W2 -I $DATA_IFACE $CONTROL_NODE_IP &>/dev/null; then
      echo "[$node] Data plane already reachable — skipping config"
      exit 0
    fi

    # Configure interface
    echo "[$node] Configuring $DATA_IFACE with $client_ip/16..."
    if ! ip addr show dev $DATA_IFACE | grep -q "$client_ip"; then
      ip addr add $client_ip/16 dev $DATA_IFACE
    fi
    ip link set dev $DATA_IFACE up
    ip link set dev $DATA_IFACE mtu $DATA_MTU
    ip route add 10.29.0.0/16 via 10.20.0.1 dev $DATA_IFACE proto static 
EOF

done
wait  # all configs done before we verify

# Verify data plane separately after all configs
IFACE_FAIL=()
for node in "${ALL_NODES[@]}"; do
  if printf '%s\n' "${SSH_FAIL[@]}" | grep -qx "$node"; then
    continue
  fi

  client_ip="${NODE_IP[$node]}"
  if ssh -o BatchMode=yes $SSH_OPTS "${SSH_USER}@${node}" \
       "ping -c9 -W2 -I $DATA_IFACE $CONTROL_NODE_IP" &>/dev/null; then
    echo "  [$node] Data plane OK ($client_ip)"
  else
    echo "  [$node] Data plane FAILED"
    IFACE_FAIL+=("$node")
  fi
done

# STEP 4: Copy udp_client binary in parallel
#echo ""
#echo "=== Copying udp_client to all reachable nodes ==="
#for node in "${ALL_NODES[@]}"; do
#  if printf '%s\n' "${SSH_FAIL[@]}" "${IFACE_FAIL[@]}" | grep -qx "$node"; then
#    continue
#  fi
#  scp $SSH_OPTS "$UDP_CLIENT_LOCAL" "${SSH_USER}@${node}:${UDP_CLIENT_REMOTE}" &
#done
#wait

# STEP 5: Verify binary is present and executable
#echo ""
#echo "=== Verifying udp_client on nodes ==="
#SCP_FAIL=()
#for node in "${ALL_NODES[@]}"; do
#  if printf '%s\n' "${SSH_FAIL[@]}" "${IFACE_FAIL[@]}" | grep -qx "$node"; then
#    continue
#  fi
#  if ssh -o BatchMode=yes $SSH_OPTS "${SSH_USER}@${node}" \
#      "chmod +x $UDP_CLIENT_REMOTE && test -x $UDP_CLIENT_REMOTE" &>/dev/null; then
#    echo "  [$node] udp_client OK"
#  else
#    echo "  [$node] udp_client FAILED"
#    SCP_FAIL+=("$node")
#  fi
#done

# SUMMARY
echo ""
echo "============================================"
echo " SETUP COMPLETE — SUMMARY"
echo "============================================"
echo "  Total nodes       : ${#ALL_NODES[@]}"
echo "  SSH failures      : ${#SSH_FAIL[@]}"
echo "  Iface failures    : ${#IFACE_FAIL[@]}"
echo "  SCP failures      : ${#SCP_FAIL[@]}"
echo "  Nodes ready       : $(( ${#ALL_NODES[@]} - ${#SSH_FAIL[@]} - ${#IFACE_FAIL[@]} - ${#SCP_FAIL[@]} ))"
echo "============================================"

# STEP 6: Generate inventory.ini from nodes.txt
echo ""
echo "=== Generating inventory.ini ==="
INVENTORY_FILE="inventory.ini"

cat > "$INVENTORY_FILE" << EOF
[clients]
EOF

while IFS=' ' read -r node ip; do
  if printf '%s\n' "${SSH_FAIL[@]}" "${IFACE_FAIL[@]}" "${SCP_FAIL[@]}" | grep -qx "$node"; then
    echo "  Skipping $node �~@~T failed during setup"
    continue
  fi
  echo "$node ansible_host=$ip" >> "$INVENTORY_FILE"
done < "$NODES_FILE"

cat >> "$INVENTORY_FILE" << EOF

[clients:vars]
ansible_user=$SSH_USER
ansible_ssh_private_key_file=~/.ssh/id_rsa
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o ConnectTimeout=10'
EOF

READY=$(grep -c "grid.orbit-lab.org" "$INVENTORY_FILE")
echo "Generated $INVENTORY_FILE with $READY ready nodes."

