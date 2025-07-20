# OpenBao Configuration for SuperMQ

This directory contains both development and production OpenBao configurations for SuperMQ certificate management.

## Overview

Two entrypoint scripts are provided:

- **`dev-entrypoint.sh`**: Development mode with in-memory storage and simple setup
- **`prod-entrypoint.sh`**: Production mode with persistent file storage and proper initialization

## Quick Start

### Development Mode (Default)
```bash
docker compose -f docker/docker-compose.yaml -f docker/addons/certs/docker-compose.yaml up -d openbao
```

### Production Mode
To switch to production mode, edit `docker-compose.yaml` and change:
```yaml
- ./dev-entrypoint.sh:/entrypoint.sh
```
to:
```yaml
- ./prod-entrypoint.sh:/entrypoint.sh
```

Then start the service:
```bash
docker compose -f docker/docker-compose.yaml -f docker/addons/certs/docker-compose.yaml up -d openbao
```

## Development Mode Features

- **In-memory storage**: No data persistence (resets on restart)
- **Development server**: Uses `-dev` flag for simple setup
- **Hardcoded tokens**: Uses predictable root token for easy access
- **Quick setup**: Minimal configuration for development
- **No unseal process**: Automatically unsealed

### Development Access
- **Root Token**: `openbao-root-token` (or `SMQ_OPENBAO_ROOT_TOKEN` env var)
- **Web UI**: http://localhost:8200/ui
- **API**: http://localhost:8200

## Production Mode Features

- **File-based storage**: Persistent storage using file backend
- **Proper initialization**: Uses unseal keys and root token
- **Security policies**: Restricted access policies for PKI operations
- **AppRole authentication**: Service-to-service authentication
- **PKI engine**: Certificate authority for SuperMQ services
- **Automatic unsealing**: Handles unsealing on container restart

### Production Security

#### Initial Setup
- On first startup, OpenBao will be automatically initialized with 5 unseal keys and 1 root token
- The initialization data is stored in `/opt/openbao/data/init.json`
- **You must backup this file securely** - it contains the unseal keys and root token

#### Access Production Instance
To get the root token and unseal keys:
```bash
docker exec supermq-openbao cat /opt/openbao/data/init.json
```

Or to get just the root token:
```bash
docker exec supermq-openbao jq -r '.root_token' /opt/openbao/data/init.json
```

#### Manual Operations
```bash
# Check status
docker exec supermq-openbao bao status

# Manual unseal (if needed)
docker exec supermq-openbao bao operator unseal <unseal-key>

# Seal vault
docker exec supermq-openbao bao operator seal
```


## Configuration Details

### Development Mode Configuration
- **Storage**: In-memory (no persistence)
- **Listener**: TCP on `0.0.0.0:8200` (TLS disabled)
- **Authentication**: Simple root token
- **PKI**: Basic setup for testing

### Production Mode Configuration
- **Storage**: File backend at `/opt/openbao/data`
- **Listener**: TCP on `0.0.0.0:8200` (TLS disabled for internal use)
- **UI**: Enabled for administration
- **Logging**: Info level
- **Initialization**: 5 unseal keys, 3 required
- **Authentication**: AppRole for services

### PKI Engine (Both Modes)
- **Path**: `/pki`
- **Root CA**: SuperMQ Root CA
- **Certificate Role**: `supermq` role for service certificates
- **Max TTL**: 720 hours (30 days) for dev, 87600 hours (10 years) for root CA in prod

### AppRole Authentication
- **Role**: `supermq`
- **Policies**: `pki-policy` (restricted PKI access)
- **Token TTL**: 1 hour (renewable up to 4 hours)

## Environment Variables

The following environment variables can be configured:

- `SMQ_CERTS_OPENBAO_APP_ROLE`: Custom AppRole ID
- `SMQ_CERTS_OPENBAO_APP_SECRET`: Custom AppRole secret
- `SMQ_OPENBAO_PORT`: OpenBao port (default: 8200)
- `SMQ_OPENBAO_ROOT_TOKEN`: Custom root token for development mode

## Switching Between Modes

### To Switch to Production Mode:
1. Edit `docker-compose.yaml`
2. Change `./dev-entrypoint.sh:/entrypoint.sh` to `./prod-entrypoint.sh:/entrypoint.sh`
3. Restart the container

### To Switch to Development Mode:
1. Edit `docker-compose.yaml`
2. Change `./prod-entrypoint.sh:/entrypoint.sh` to `./dev-entrypoint.sh:/entrypoint.sh`
3. Restart the container

## Backup and Recovery (Production Mode)

### Creating Backups
```bash
# Create backup of OpenBao data
docker exec supermq-openbao tar -czf /tmp/backup.tar.gz -C /opt/openbao data config
docker cp supermq-openbao:/tmp/backup.tar.gz ./openbao-backup-$(date +%Y%m%d).tar.gz
```

### Restoring Backups
```bash
# Stop container
docker stop supermq-openbao

# Restore data
docker cp backup.tar.gz supermq-openbao:/tmp/restore.tar.gz
docker start supermq-openbao
docker exec supermq-openbao sh -c "cd /opt/openbao && tar -xzf /tmp/restore.tar.gz"

# Restart container
docker restart supermq-openbao
```

## Production Deployment Recommendations

### High Availability
- Deploy multiple OpenBao instances with shared storage
- Use external storage backends (Consul, etcd, etc.) for HA
- Implement load balancing for OpenBao endpoints

### Security Hardening
1. **Enable TLS**: Configure TLS certificates for HTTPS access
2. **Network Security**: Restrict network access to OpenBao
3. **Audit Logging**: Enable audit logs for compliance
4. **Secret Management**: Use external secret management for unseal keys
5. **Regular Backups**: Automate backup creation and testing

### Monitoring
- Monitor OpenBao health endpoints
- Set up alerts for seal/unseal events
- Track certificate issuance and expiration

## Troubleshooting

### Common Issues

**OpenBao is sealed (Production)**:
```bash
# Get unseal keys
KEYS=$(docker exec supermq-openbao jq -r '.unseal_keys_b64[]' /opt/openbao/data/init.json)

# Unseal (need 3 keys)
docker exec supermq-openbao bao operator unseal <key1>
docker exec supermq-openbao bao operator unseal <key2>
docker exec supermq-openbao bao operator unseal <key3>
```

**Cannot connect to OpenBao**:
- Check container is running: `docker ps`
- Check logs: `docker logs supermq-openbao`
- Verify port mapping in docker-compose.yaml

**Lost access credentials**:
- **Development**: Use default root token `openbao-root-token`
- **Production**: Check `/opt/openbao/data/init.json` for root token

**Certificate operations fail**:
- Verify AppRole credentials
- Check PKI policy permissions
- Ensure PKI engine is enabled

### Logs and Debugging
```bash
# View OpenBao logs
docker logs supermq-openbao

# Check OpenBao status
docker exec supermq-openbao bao status

# Debug container
docker exec -it supermq-openbao sh
```

## Security Considerations

- **Never expose OpenBao directly to the internet**
- **Regularly rotate AppRole secrets**
- **Monitor for unauthorized access attempts**
- **Keep OpenBao updated to latest security patches**
- **Use network segmentation to isolate OpenBao**
- **In production, enable TLS and proper authentication**
