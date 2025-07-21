#!/bin/sh
# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0

set -e

apk add --no-cache jq

mkdir -p /opt/openbao/config /opt/openbao/data /opt/openbao/logs

cat > /opt/openbao/config/config.hcl << 'EOF'
storage "file" {
  path = "/opt/openbao/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

ui = true
log_level = "Info"
disable_mlock = true

# API timeout settings
default_lease_ttl = "168h"
max_lease_ttl = "720h"
EOF

export BAO_ADDR=http://localhost:8200

if [ ! -f /opt/openbao/data/init.json ]; then
  bao server -config=/opt/openbao/config/config.hcl > /opt/openbao/logs/server.log 2>&1 &
  BAO_PID=$!
  
  bao operator init -key-shares=5 -key-threshold=3 -format=json > /opt/openbao/data/init.json
  
  UNSEAL_KEY_1=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[0]')
  UNSEAL_KEY_2=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[1]')
  UNSEAL_KEY_3=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[2]')
  ROOT_TOKEN=$(cat /opt/openbao/data/init.json | jq -r '.root_token')
  
  bao operator unseal $UNSEAL_KEY_1
  bao operator unseal $UNSEAL_KEY_2
  bao operator unseal $UNSEAL_KEY_3
  
  export BAO_TOKEN=$ROOT_TOKEN
  
else
  bao server -config=/opt/openbao/config/config.hcl > /opt/openbao/logs/server.log 2>&1 &
  BAO_PID=$!
  
  if bao status | grep -q "Sealed.*true"; then
    echo "OpenBao is sealed, attempting to unseal..."
    
    UNSEAL_KEY_1=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[0]')
    UNSEAL_KEY_2=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[1]')
    UNSEAL_KEY_3=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[2]')
    
    bao operator unseal $UNSEAL_KEY_1
    bao operator unseal $UNSEAL_KEY_2
    bao operator unseal $UNSEAL_KEY_3
  fi
  
  ROOT_TOKEN=$(cat /opt/openbao/data/init.json | jq -r '.root_token')
  export BAO_TOKEN=$ROOT_TOKEN
fi

if [ ! -f /opt/openbao/data/configured ]; then
  echo "Enabling authentication and secrets engines..."
  bao auth enable approle || echo "AppRole already enabled"
  bao secrets enable -path=pki pki || echo "PKI already enabled"

  echo "Configuring PKI engine..."
  bao secrets tune -max-lease-ttl=87600h pki
  
  bao write -field=certificate pki/root/generate/internal \
    common_name='SuperMQ Root CA' \
    ttl=87600h \
    key_bits=2048 \
    exclude_cn_from_sans=true

  bao write pki/config/urls \
    issuing_certificates='http://localhost:8200/v1/pki/ca' \
    crl_distribution_points='http://localhost:8200/v1/pki/crl'

  bao write pki/roles/supermq \
    allow_any_name=true \
    enforce_hostnames=false \
    allow_ip_sans=true \
    allow_localhost=true \
    max_ttl=720h \
    ttl=720h \
    key_bits=2048

  cat > /opt/openbao/config/pki-policy.hcl << 'EOF'
path "pki/issue/supermq" {
  capabilities = ["create", "update"]
}

path "pki/certs" {
  capabilities = ["list"]
}

path "pki/cert/*" {
  capabilities = ["read"]
}

path "pki/revoke" {
  capabilities = ["create", "update"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
EOF

  bao policy write pki-policy /opt/openbao/config/pki-policy.hcl

  echo "Configuring AppRole authentication..."
  bao write auth/approle/role/supermq \
    token_policies=pki-policy \
    token_ttl=1h \
    token_max_ttl=4h \
    bind_secret_id=true \
    secret_id_ttl=24h

  if [ -n "$SMQ_CERTS_OPENBAO_APP_ROLE" ]; then
    bao write auth/approle/role/supermq/role-id role_id="$SMQ_CERTS_OPENBAO_APP_ROLE"
  fi

  if [ -n "$SMQ_CERTS_OPENBAO_APP_SECRET" ]; then
    bao write auth/approle/role/supermq/custom-secret-id secret_id="$SMQ_CERTS_OPENBAO_APP_SECRET"
  fi

  SERVICE_TOKEN=$(bao write -field=token auth/token/create \
    policies=pki-policy \
    ttl=24h \
    renewable=true \
    display_name="supermq-service")
  
  echo "SERVICE_TOKEN=$SERVICE_TOKEN" > /opt/openbao/data/service_token
  
  touch /opt/openbao/data/configured
  
  echo "OpenBao configuration completed successfully!"
else
  echo "OpenBao already configured, skipping setup..."
fi

echo "================================"
echo "OpenBao Production Setup Complete"
echo "================================"
echo "OpenBao Address: http://localhost:8200"
echo "UI Available at: http://localhost:8200/ui"
echo "Root Token: $(cat /opt/openbao/data/init.json | jq -r '.root_token')"
echo "Service Token: $(cat /opt/openbao/data/service_token 2>/dev/null | cut -d= -f2 || echo 'Not available')"
echo "================================"
echo "IMPORTANT: Store the init.json file securely!"
echo "It contains unseal keys and root token!"
echo "================================"

echo "OpenBao is ready for SuperMQ on port 8200"
wait $BAO_PID
