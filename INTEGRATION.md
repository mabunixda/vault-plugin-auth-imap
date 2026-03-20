# Vault IMAP Authentication Plugin - Integration Guide

## Overview
This guide helps you integrate the Vault IMAP Authentication Plugin into your HashiCorp Vault deployment.

## Prerequisites
- HashiCorp Vault 1.12+
- IMAP/IMAPS server (Gmail, Exchange, etc.)
- Go 1.24+ (for building from source)

## Installation

### Method 1: Download Binary
```bash
# Download from releases
wget https://github.com/mabunixda/vault-plugin-auth-imap/releases/latest/download/vault-plugin-auth-imap-linux-amd64
```

### Method 2: Build from Source
```bash
git clone https://github.com/mabunixda/vault-plugin-auth-imap.git
cd vault-plugin-auth-imap
make build
```

## Configuration Examples

### Gmail Integration
```hcl
resource "vault_auth_backend" "imap" {
  type = "vault-plugin-auth-imap"
  path = "imap"
}

resource "vault_generic_secret" "imap_config" {
  path = "auth/imap/config"
  data_json = jsonencode({
    imap_server = "imap.gmail.com"
    imap_port   = 993
    imap_ssl    = true
    secure_nonce = true
  })
}
```

### Enterprise Use Cases
- **Corporate Email Authentication**: Authenticate users with existing email credentials
- **Temporary Access**: Use secure nonces for time-limited access
- **Multi-Factor Authentication**: Combine with other auth methods
- **Audit Compliance**: Detailed logging of authentication attempts

## Monitoring and Observability
- Vault audit logs capture all authentication attempts
- Metrics available through Vault telemetry
- Health checks via Vault API

## Security Considerations
- Always use SSL/TLS (port 993 for IMAPS)
- Enable secure nonce validation for enhanced security
- Implement IP-based access restrictions
- Regular credential rotation policies

## Troubleshooting
Common issues and solutions...

## Support
- GitHub Issues: https://github.com/mabunixda/vault-plugin-auth-imap/issues
- Documentation: https://github.com/mabunixda/vault-plugin-auth-imap/blob/main/README.md
