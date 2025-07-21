#!/bin/sh
# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0

set -e

bao server -dev \
  -dev-root-token-id="${BAO_DEV_ROOT_TOKEN_ID}" \
  -dev-listen-address="0.0.0.0:8200" \
  -log-level=info &

BAO_PID=$!

export BAO_ADDR=http://localhost:8200
export BAO_TOKEN="${BAO_DEV_ROOT_TOKEN_ID}"

bao auth enable approle 2>/dev/null || echo "AppRole already enabled"
bao secrets enable -path=pki pki 2>/dev/null || echo "PKI already enabled"

bao secrets tune -max-lease-ttl=87600h pki >/dev/null 2>&1 || true
bao write -field=certificate pki/root/generate/internal \
  common_name='SuperMQ Root CA' ttl=87600h >/dev/null 2>&1 || true

bao write pki/config/urls \
  issuing_certificates='http://localhost:8200/v1/pki/ca' \
  crl_distribution_points='http://localhost:8200/v1/pki/crl' >/dev/null 2>&1 || true

bao write pki/roles/supermq \
  allow_any_name=true enforce_hostnames=false allow_ip_sans=true \
  allow_localhost=true max_ttl=720h ttl=720h >/dev/null 2>&1 || true

cat > /tmp/policy.hcl << 'EOF'
path "pki/issue/supermq" { capabilities = ["create", "update"] }
path "pki/certs" { capabilities = ["list"] }
path "pki/cert/*" { capabilities = ["read"] }
path "pki/revoke" { capabilities = ["create", "update"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
EOF

bao policy write pki-policy /tmp/policy.hcl >/dev/null 2>&1 || true

bao write auth/approle/role/supermq \
  token_policies=pki-policy token_ttl=1h token_max_ttl=4h renewable=true \
  bind_secret_id=true >/dev/null 2>&1 || true

if [ -n "$SMQ_CERTS_OPENBAO_APP_ROLE" ]; then
  bao write auth/approle/role/supermq/role-id role_id="$SMQ_CERTS_OPENBAO_APP_ROLE" >/dev/null 2>&1 || true
fi

if [ -n "$SMQ_CERTS_OPENBAO_APP_SECRET" ]; then
  bao write auth/approle/role/supermq/custom-secret-id secret_id="$SMQ_CERTS_OPENBAO_APP_SECRET" >/dev/null 2>&1 || true
fi

echo "OpenBao configuration completed successfully!"
echo "OpenBao is ready for SuperMQ on port 8200"
echo "Root Token: ${BAO_DEV_ROOT_TOKEN_ID}"

wait $BAO_PID
