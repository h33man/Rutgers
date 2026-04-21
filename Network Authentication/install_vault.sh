#! /bin/bash

#Step 1 Generate Certs (on the Vault machine 192.168.100.3)
mkdir -p ~/xdp-pki && cd ~/xdp-pki
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -days 3650 -out ca.pem \
  -subj "/C=US/O=XDP/CN=XDP-CA"
#Create the Vault server cert (SAN must include the IP):
openssl genrsa -out vault.key 2048

openssl req -new -key vault.key \
  -subj "/C=US/O=XDP/CN=192.168.100.3" \
  -out vault.csr

# SAN config IP address required for curl to verify the cert
cat > vault-ext.cnf <<EOF
[req]
req_extensions = v3_req
[v3_req]
subjectAltName = IP:192.168.100.3
EOF

openssl x509 -req -in vault.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 365 -out vault.pem \
  -extfile vault-ext.cnf \
  -extensions v3_req
#Create the client cert (for 192.168.100.2):
openssl genrsa -out client.key 2048

openssl req -new -key client.key \
  -subj "/C=US/O=XDP/CN=xdp-client" \
  -out client.csr

openssl x509 -req -in client.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 365 -out client.pem

#openssl genrsa -out server.key 2048

openssl req -new -key server.key \
  -subj "/C=US/O=XDP/CN=xdp-server" \
  -out server.csr

openssl x509 -req -in server.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 365 -out server.pem

openssl x509 -in vault.pem -text -noout | grep -A1 "Subject Alternative"

#Step 2 Install Vault (on 192.168.100.3)
sudo apt update && sudo apt install -y gpg wget

wget -O- https://apt.releases.hashicorp.com/gpg | \
  sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
  https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
  sudo tee /etc/apt/sources.list.d/hashicorp.list

sudo apt update && sudo apt install -y vault

#Step 3 Configure Vault (on 192.168.100.3)
sudo mkdir -p /etc/vault.d /opt/vault/data

# Copy certs to Vault's config directory
sudo cp ~/xdp-pki/vault.pem /etc/vault.d/vault.pem
sudo cp ~/xdp-pki/vault.key /etc/vault.d/vault.key
sudo cp ~/xdp-pki/ca.pem    /etc/vault.d/ca.pem
sudo chown -R vault:vault /etc/vault.d

sudo tee /etc/vault.d/vault.hcl <<EOF
ui            = false
disable_mlock = false

storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address            = "0.0.0.0:8200"
  tls_cert_file      = "/etc/vault.d/vault.pem"
  tls_key_file       = "/etc/vault.d/vault.key"
  tls_client_ca_file = "/etc/vault.d/ca.pem"
}

api_addr = "https://192.168.100.3:8200"
EOF

sudo chown vault:vault /etc/vault.d/vault.hcl
sudo chown -R vault:vault /opt/vault

#Step 4 Start and Initialise Vault (on 192.168.100.3)
sudo systemctl enable vault
sudo systemctl start vault
sudo systemctl status vault   # confirm it's running

export VAULT_ADDR="https://192.168.100.3:8200"
export VAULT_CACERT="/etc/vault.d/ca.pem"

#Initialise: this is a one-time operation:
vault operator init -key-shares=1 -key-threshold=1

#Unseal:
vault operator unseal <unseal_key>

#Login with root token:
vault login hvs.xxxxxxxxxxxxxxxx

#Step 5 Configure KV v2 and Expiry (on 192.168.100.3)
# Enable KV v2 at the "secret" mount
vault secrets enable -version=2 -path=secret kv

# Set 24-hour delete_version_after on the networks path
# This means Vault automatically deletes any secret written here after 24h
vault kv metadata put \
  -mount=secret \
  -custom-metadata=managed=true \
  -delete-version-after=24h \
  secret/networks

#Step 6 Enable TLS Cert Auth and Policy (on 192.168.100.3)
# Enable cert auth
vault auth enable cert

# Create a policy allowing read on all keys under networks/
vault policy write xdp-read-policy - <<EOF
path "secret/data/networks/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/networks/*" {
  capabilities = ["read", "list"]
}
EOF

# Register the CA any cert signed by it gets the xdp-read-policy
vault write auth/cert/certs/xdp-ca \
  display_name="xdp-ca" \
  policies="xdp-read-policy" \
  certificate=@/etc/vault.d/ca.pem \
  ttl=3600

#Step 7 Distribute Certs to Client and Server
# To client (192.168.100.2)
ssh 192.168.100.2 "sudo mkdir -p /etc/xdp/certs"
sudo scp ~/xdp-pki/ca.pem      192.168.100.2:/etc/xdp/certs/ca.pem
sudo scp ~/xdp-pki/client.pem  192.168.100.2:/etc/xdp/certs/client.pem
sudo scp ~/xdp-pki/client.key  192.168.100.2:/etc/xdp/certs/client-key.pem

# To server (192.168.100.1)
ssh 192.168.100.1 "sudo mkdir -p /etc/xdp/certs"
sudo scp ~/xdp-pki/ca.pem      192.168.100.1:/etc/xdp/certs/ca.pem
sudo scp ~/xdp-pki/server.pem  192.168.100.1:/etc/xdp/certs/client.pem
sudo scp ~/xdp-pki/server.key  192.168.100.1:/etc/xdp/certs/client-key.pem

#Lock down permissions on both machines:
sudo chmod 600 /etc/xdp/certs/client-key.pem
sudo chmod 644 /etc/xdp/certs/ca.pem /etc/xdp/certs/client.pem

#Step 8 Test the Setup (on 192.168.100.3)
#Write a test key as the daemon would:
vault kv put secret/networks/192.168.100.0/24 \
  key="4b758f9498d3312616ecc26199437645"
vault kv get secret/networks/192.168.100.0/24

#Test cert auth from the client machine (192.168.100.2):
curl --cacert /etc/xdp/certs/ca.pem \
     --cert   /etc/xdp/certs/client.pem \
     --key    /etc/xdp/certs/client-key.pem \
     https://192.168.100.3:8200/v1/auth/cert/login \
     -X POST
# Should return JSON with auth.client_token

#Test a full key fetch:
curl --cacert /etc/xdp/certs/ca.pem \
     --cert   /etc/xdp/certs/client.pem \
     --key    /etc/xdp/certs/client-key.pem \
     -H "X-Vault-Token: <token_from_above>" \
     https://192.168.100.3:8200/v1/secret/data/networks/192.168.100.0/24
# Should return JSON with data.data.key
