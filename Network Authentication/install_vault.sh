#! /bin/bash

#Step 1 Generate Certs (on the Vault machine 10.20.21.1)
mkdir -p ~/liha-pki && cd ~/liha-pki
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -days 3650 -out ca.pem \
  -subj "/C=US/O=LIHA/CN=LIHA-CA"
#Create the Vault server cert (SAN must include the IP):
openssl genrsa -out vault.key 2048

openssl req -new -key vault.key \
  -subj "/C=US/O=LIHA/CN=10.20.21.1" \
  -out vault.csr

# SAN config IP address required for curl to verify the cert
cat > vault-ext.cnf <<EOF
[req]
req_extensions = v3_req
[v3_req]
subjectAltName = IP:10.20.21.1
EOF

openssl x509 -req -in vault.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 365 -out vault.pem \
  -extfile vault-ext.cnf \
  -extensions v3_req
#Create the client cert (for 10.29.1.6):
openssl genrsa -out client.key 2048

openssl req -new -key client.key \
  -subj "/C=US/O=LIHA/CN=liha-client" \
  -out client.csr

openssl x509 -req -in client.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 365 -out client.pem

openssl genrsa -out server.key 2048

openssl req -new -key server.key \
  -subj "/C=US/O=LIHA/CN=liha-server" \
  -out server.csr

openssl x509 -req -in server.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 365 -out server.pem

openssl x509 -in vault.pem -text -noout | grep -A1 "Subject Alternative"

# Generate daemon cert
openssl genrsa -out daemon.key 2048

openssl req -new -key daemon.key \
    -subj "/C=US/O=LIHA/CN=liha-daemon" \
    -out daemon.csr

cat > daemon-ext.cnf <<EOF
[v3_req]
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in daemon.csr \
    -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 365 -out daemon.pem \
    -extfile daemon-ext.cnf \
    -extensions v3_req

#Step 2 Install Vault (on 10.20.21.1)
sudo apt update && sudo apt install -y gpg wget

wget -O- https://apt.releases.hashicorp.com/gpg | \
  sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
  https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
  sudo tee /etc/apt/sources.list.d/hashicorp.list

sudo apt update && sudo apt install -y vault

#Step 3 Configure Vault (on 10.20.21.1)
sudo mkdir -p /etc/vault.d /opt/vault/data

# Copy certs to Vault's config directory
sudo cp ~/liha-pki/vault.pem /etc/vault.d/vault.pem
sudo cp ~/liha-pki/vault.key /etc/vault.d/vault.key
sudo cp ~/liha-pki/ca.pem    /etc/vault.d/ca.pem
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

api_addr = "https://10.20.21.1:8200"
EOF

sudo chown vault:vault /etc/vault.d/vault.hcl
sudo chown -R vault:vault /opt/vault

#Step 4 Start and Initialise Vault (on 10.20.21.1)
sudo systemctl enable vault
sudo systemctl start vault
sudo systemctl status vault   # confirm it's running

export VAULT_ADDR="https://10.20.21.1:8200"
export VAULT_CACERT="/etc/vault.d/ca.pem"

#Initialise: this is a one-time operation:
vault operator init -key-shares=1 -key-threshold=1

exit()

#Unseal:
vault operator unseal <unseal_key>

#Login with root token:
vault login hvs.xxxxxxxxxxxxxxxx

#Step 5 Configure KV v2 and Expiry (on 10.20.21.1)
# Enable KV v2 at the "secret" mount
vault secrets enable -version=2 -path=secret kv

# Set 24-hour delete_version_after on the networks path
# This means Vault automatically deletes any secret written here after 24h
vault kv metadata put \
  -mount=secret \
  -custom-metadata=managed=true \
  -delete-version-after=24h \
  secret/data/networks

#Change the expiry using this command
#vault kv metadata put -delete-version-after=1m  secret/data/networks

#Step 6 Enable TLS Cert Auth and Policy (on 10.20.21.1)
# Enable cert auth
vault auth enable cert

# Create a policy allowing read on all keys under networks/
vault policy write liha-read-policy - <<EOF
path "secret/data/networks/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/networks/*" {
  capabilities = ["read", "list"]
}
EOF

# Register the CA any cert signed by it gets the liha-read-policy
vault write auth/cert/certs/liha-ca \
  display_name="liha-ca" \
  policies="liha-read-policy" \
  certificate=@/etc/vault.d/ca.pem \
  ttl=3600

#Step 7 Distribute Certs to Client and Server
# To client (10.29.1.6)
ssh 10.29.1.6 "sudo mkdir -p /etc/liha/certs"
sudo scp ~/liha-pki/ca.pem      10.29.1.6:/etc/liha/certs/ca.pem
sudo scp ~/liha-pki/client.pem  10.29.1.6:/etc/liha/certs/client.pem
sudo scp ~/liha-pki/client.key  10.29.1.6:/etc/liha/certs/client-key.pem

#Lock down permissions on both machines:
ssh 10.29.1.6 "sudo chmod 600 /etc/liha/certs/client-key.pem && \
sudo chmod 644 /etc/liha/certs/ca.pem /etc/liha/certs/client.pem"

# To server (10.29.1.4)
ssh 10.29.1.4 "sudo mkdir -p /etc/liha/certs"
sudo scp ~/liha-pki/ca.pem      10.29.1.4:/etc/liha/certs/ca.pem
sudo scp ~/liha-pki/server.pem  10.29.1.4:/etc/liha/certs/client.pem
sudo scp ~/liha-pki/server.key  10.29.1.4:/etc/liha/certs/client-key.pem
ssh 10.29.1.4 "sudo chmod 600 /etc/liha/certs/client-key.pem && \
sudo chmod 644 /etc/liha/certs/ca.pem /etc/liha/certs/client.pem"


#Step 8 Test the Setup (on 10.20.21.1)
#Write a test key as the daemon would:
vault kv put secret/data/networks/10.29.0.0/16 \
  key="4b758f9498d3312616ecc261994376452a3b4c5d6e7f8091a2b3c4d5e6f708191a2b3c4d5e6f708192a3b4c5d6e7f8090a1b2c3d4e5f60718293a4b5c6d7e8f9"
vault kv get secret/data/networks/10.29.0.0/16

#Test cert auth from the client machine (10.29.1.6):
curl --cacert /etc/liha/certs/ca.pem \
     --cert   /etc/liha/certs/client.pem \
     --key    /etc/liha/certs/client-key.pem \
     https://10.20.21.1:8200/v1/auth/cert/login \
     -X POST
# Should return JSON with auth.client_token

#Test a full key fetch:
curl --cacert /etc/liha/certs/ca.pem \
     --cert   /etc/liha/certs/client.pem \
     --key    /etc/liha/certs/client-key.pem \
     -H "X-Vault-Token: <token_from_above>" \
     https://10.20.21.1:8200/v1/secret/data/networks/10.29.0.0/16
# Should return JSON with data.data.key
