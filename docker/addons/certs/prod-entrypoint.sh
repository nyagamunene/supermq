#!/bin/sh

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
  echo "Initializing OpenBao for first time..."
  
  bao server -config=/opt/openbao/config/config.hcl > /opt/openbao/logs/server.log 2>&1 &
  BAO_PID=$!
  echo "OpenBao started with PID: $BAO_PID"
  
  # Wait for OpenBao to be ready
  echo "Waiting for OpenBao to be ready..."
  sleep 15
  
  # Initialize OpenBao
  echo "Initializing OpenBao..."
  bao operator init -key-shares=5 -key-threshold=3 -format=json > /opt/openbao/data/init.json
  
  # Extract unseal keys and root token
  UNSEAL_KEY_1=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[0]')
  UNSEAL_KEY_2=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[1]')
  UNSEAL_KEY_3=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[2]')
  ROOT_TOKEN=$(cat /opt/openbao/data/init.json | jq -r '.root_token')
  
  # Unseal OpenBao
  echo "Unsealing OpenBao..."
  bao operator unseal $UNSEAL_KEY_1
  bao operator unseal $UNSEAL_KEY_2
  bao operator unseal $UNSEAL_KEY_3
  
  export BAO_TOKEN=$ROOT_TOKEN
  
else
  echo "OpenBao already initialized, starting server..."
  
  # Start OpenBao in the background
  bao server -config=/opt/openbao/config/config.hcl > /opt/openbao/logs/server.log 2>&1 &
  BAO_PID=$!
  echo "OpenBao started with PID: $BAO_PID"
  
  # Wait for OpenBao to be ready
  echo "Waiting for OpenBao to be ready..."
  sleep 10
  
  # Check if unsealing is needed
  if bao status | grep -q "Sealed.*true"; then
    echo "OpenBao is sealed, attempting to unseal..."
    
    # Extract unseal keys from init file
    UNSEAL_KEY_1=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[0]')
    UNSEAL_KEY_2=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[1]')
    UNSEAL_KEY_3=$(cat /opt/openbao/data/init.json | jq -r '.unseal_keys_b64[2]')
    
    # Unseal OpenBao
    bao operator unseal $UNSEAL_KEY_1
    bao operator unseal $UNSEAL_KEY_2
    bao operator unseal $UNSEAL_KEY_3
  fi
  
  # Get root token for configuration
  ROOT_TOKEN=$(cat /opt/openbao/data/init.json | jq -r '.root_token')
  export BAO_TOKEN=$ROOT_TOKEN
fi

# Check if configuration already exists
if [ ! -f /opt/openbao/data/configured ]; then
  echo "Configuring OpenBao for SuperMQ..."

  # Enable required engines
  echo "Enabling authentication and secrets engines..."
  bao auth enable approle || echo "AppRole already enabled"
  bao secrets enable -path=pki pki || echo "PKI already enabled"

  # Configure PKI engine
  echo "Configuring PKI engine..."
  bao secrets tune -max-lease-ttl=87600h pki
  
  # Generate root CA certificate
  bao write -field=certificate pki/root/generate/internal \
    common_name='SuperMQ Root CA' \
    ttl=87600h \
    key_bits=2048 \
    exclude_cn_from_sans=true

  # Configure PKI URLs
  bao write pki/config/urls \
    issuing_certificates='http://localhost:8200/v1/pki/ca' \
    crl_distribution_points='http://localhost:8200/v1/pki/crl'

  # Create PKI role for SuperMQ
  bao write pki/roles/supermq \
    allow_any_name=true \
    enforce_hostnames=false \
    allow_ip_sans=true \
    allow_localhost=true \
    max_ttl=720h \
    ttl=720h \
    key_bits=2048

  # Create security policy for PKI operations
  cat > /opt/openbao/config/pki-policy.hcl << 'EOF'
# PKI policy for SuperMQ certificate operations
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

  # Configure AppRole for SuperMQ
  echo "Configuring AppRole authentication..."
  bao write auth/approle/role/supermq \
    token_policies=pki-policy \
    token_ttl=1h \
    token_max_ttl=4h \
    bind_secret_id=true \
    secret_id_ttl=24h

  # Set custom credentials if provided via environment variables
  if [ -n "$SMQ_CERTS_OPENBAO_APP_ROLE" ]; then
    echo "Setting custom AppRole ID..."
    bao write auth/approle/role/supermq/role-id role_id="$SMQ_CERTS_OPENBAO_APP_ROLE"
  fi

  if [ -n "$SMQ_CERTS_OPENBAO_APP_SECRET" ]; then
    echo "Setting custom AppRole secret..."
    bao write auth/approle/role/supermq/custom-secret-id secret_id="$SMQ_CERTS_OPENBAO_APP_SECRET"
  fi

  # Create a service token for SuperMQ operations (alternative to AppRole)
  echo "Creating service token for SuperMQ..."
  SERVICE_TOKEN=$(bao write -field=token auth/token/create \
    policies=pki-policy \
    ttl=24h \
    renewable=true \
    display_name="supermq-service")
  
  echo "SERVICE_TOKEN=$SERVICE_TOKEN" > /opt/openbao/data/service_token
  
  # Mark configuration as complete
  touch /opt/openbao/data/configured
  
  echo "OpenBao configuration completed successfully!"
else
  echo "OpenBao already configured, skipping setup..."
fi

# Display connection information
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

# Keep the process running
echo "OpenBao is ready for SuperMQ on port 8200"
wait $BAO_PID
