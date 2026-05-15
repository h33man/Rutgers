#!/bin/bash
# /usr/local/bin/vault-key-daemon.sh

VAULT_ADDR="https://10.20.21.1:8200"
VAULT_CACERT="/etc/liha/certs/ca.pem"
VAULT_CLIENT_CERT="/etc/liha/certs/daemon.pem"
VAULT_CLIENT_KEY="/etc/liha/certs/daemon-key.pem"

# List of networks to manage
NETWORKS=(
    "10.29.0.0/16"
    "10.20.0.0/16"
)

export VAULT_ADDR VAULT_CACERT

get_vault_token() {
    curl -s \
        --cacert "$VAULT_CACERT" \
        --cert   "$VAULT_CLIENT_CERT" \
        --key    "$VAULT_CLIENT_KEY" \
        -X POST \
        "${VAULT_ADDR}/v1/auth/cert/login" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])"
}

generate_key() {
    openssl rand -hex 64
}

write_key() {
    local token="$1"
    local network="$2"
    local key="$3"

    # Split network into address and prefix — e.g. "10.29.0.0/16"
    # → path: secret/networks/10.29.0.0/16
    local path="secret/networks/${network}"

    curl -s \
        --cacert "$VAULT_CACERT" \
        --cert   "$VAULT_CLIENT_CERT" \
        --key    "$VAULT_CLIENT_KEY" \
        -H "X-Vault-Token: ${token}" \
        -H "Content-Type: application/json" \
        -X POST \
        -d "{\"data\": {\"key\": \"${key}\"}}" \
        "${VAULT_ADDR}/v1/${path}" > /dev/null

    return $?
}

echo "Vault key daemon started — managing ${#NETWORKS[@]} networks"

while true; do
    # Re-authenticate each cycle — token TTL is 1 hour by default
    TOKEN=$(get_vault_token)
    if [ -z "$TOKEN" ]; then
        echo "$(date): ERROR: Failed to authenticate to Vault" >&2
        sleep 10
        continue
    fi

    # Write a fresh independent key for each network
    for NETWORK in "${NETWORKS[@]}"; do
        KEY=$(generate_key)
        write_key "$TOKEN" "$NETWORK" "$KEY"

        if [ $? -eq 0 ]; then
            echo "$(date): New key written for ${NETWORK}"
        else
            echo "$(date): ERROR writing key for ${NETWORK}" >&2
        fi
    done

    sleep 30   # Write every 30s, expire after 1m — safe overlap window
done
