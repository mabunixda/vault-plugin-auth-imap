# Vault IMAP Authentication Plugin

[![CI](https://github.com/mabunixda/vault-plugin-auth-imap/actions/workflows/ci.yml/badge.svg)](https://github.com/mabunixda/vault-plugin-auth-imap/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/Coverage-75.7%25-brightgreen)](https://github.com/mabunixda/vault-plugin-auth-imap)
[![Go Report Card](https://goreportcard.com/badge/github.com/mabunixda/vault-plugin-auth-imap)](https://goreportcard.com/report/github.com/mabunixda/vault-plugin-auth-imap)
[![License](https://img.shields.io/github/license/mabunixda/vault-plugin-auth-imap)](LICENSE)
[![Release](https://img.shields.io/github/v/release/mabunixda/vault-plugin-auth-imap)](https://github.com/mabunixda/vault-plugin-auth-imap/releases)

This is a standalone backend plugin for use with [HashiCorp Vault](https://www.github.com/hashicorp/vault).
This plugin allows users to authenticate to Vault using their IMAP email credentials, supporting both traditional IMAP and secure IMAPS connections.

## ✨ Features

- 🔒 **Enterprise Security Ready** - Comprehensive security hardening with input validation and ReDoS protection
- 🛡️ **Multiple Connection Types** - Support for IMAP, IMAPS (SSL/TLS), and STARTTLS connections
- 🎯 **Flexible Principal Matching** - Support for exact matches and regex patterns for email validation
- 🔐 **Secure Nonce Support** - Optional secure nonce validation for enhanced security
- ⚡ **High Performance** - Optimized connection management with configurable timeouts
- 🧪 **Thoroughly Tested** - 75.7% test coverage with comprehensive edge case validation
- 🏗️ **Production Ready** - Modular architecture with robust error handling

## 🚀 Quick Start

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html) designed to work seamlessly with HashiCorp Vault. This guide assumes you have Vault installed and understand the basics of Vault operations.

**New to Vault?** Start with the [official getting started guide](https://www.vaultproject.io/intro/getting-started/install.html).

**Want to learn about plugins?** Check out the [Vault plugins documentation](https://www.vaultproject.io/docs/internals/plugins.html).

## 📖 Usage

### 1. Enable the Plugin

```bash
# Download and install the plugin binary to your Vault plugins directory
# Then register and enable it
vault auth enable -path=imap vault-plugin-auth-imap
```
```
Success! Enabled vault-plugin-auth-imap auth method at: imap/
```

### 2. Configure the Plugin

Configure your IMAP server connection with these parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `imap_server` | string | *required* | IMAP server hostname or IP address |
| `imap_port` | int | `993` | IMAP server port |
| `imap_ssl` | bool | `true` | Enable SSL/TLS encryption (IMAPS) |
| `use_starttls` | bool | `false` | Use STARTTLS for encryption |
| `skip_tls_verify` | bool | `false` | Skip TLS certificate verification |
| `connection_timeout` | duration | `30s` | Connection timeout |
| `secure_nonce` | bool | `false` | Enable secure nonce validation |

#### Basic Configuration (IMAPS)
```bash
vault write auth/imap/config \
    imap_server="imap.gmail.com" \
    imap_port=993 \
    imap_ssl=true
```

#### STARTTLS Configuration
```bash
vault write auth/imap/config \
    imap_server="imap.example.com" \
    imap_port=143 \
    use_starttls=true \
    imap_ssl=false
```

#### Enhanced Security Configuration
```bash
vault write auth/imap/config \
    imap_server="imap.company.com" \
    imap_port=993 \
    imap_ssl=true \
    secure_nonce=true \
    connection_timeout="60s"
```

### 3. Create Authentication Roles

Roles define which users can authenticate and what policies they receive. You can create roles with specific email restrictions or allow all valid IMAP users.

#### Role with Specific Email Addresses
```bash
vault write auth/imap/role/admin-users \
    token_policies="admin-policy,audit-policy" \
    token_ttl="8h" \
    token_max_ttl="24h" \
    principals="admin@company.com,security@company.com"
```

#### Role with Regex Pattern Matching
```bash
vault write auth/imap/role/company-employees \
    token_policies="employee-policy" \
    token_ttl="12h" \
    principals=".*@company\.com$,.*@subsidiary\.company\.com$"
```

#### Role for All Valid Users
```bash
vault write auth/imap/role/all-users \
    token_policies="readonly-policy" \
    token_ttl="4h" \
    token_max_ttl="12h"
```

#### Role with IP Restrictions
```bash
vault write auth/imap/role/office-only \
    token_policies="office-policy" \
    token_bound_cidrs="192.168.1.0/24,10.0.0.0/8" \
    principals=".*@company\.com$"
```

### 4. Authenticate with IMAP Credentials

Users can now authenticate using their email and password with any configured role:

#### Basic Authentication
```bash
vault write auth/imap/login \
    role="company-employees" \
    username="john.doe@company.com" \
    password="secure-password"
```

#### Authentication with Secure Nonce (if enabled)
```bash
# First, get a nonce
vault read auth/imap/nonce

# Then authenticate with the nonce
vault write auth/imap/login \
    role="admin-users" \
    username="admin@company.com" \
    password="admin-password" \
    nonce="base64-encoded-nonce"
```

#### Successful Authentication Response
```
Key                  Value
---                  -----
token                hvs.CAESICPJO73kqtz...
token_accessor       4s1lxJvhvKl9Oq6CbZuXEcpY
token_duration       8h
token_renewable      true
token_policies       ["default", "admin-policy", "audit-policy"]
identity_policies    []
policies             ["default", "admin-policy", "audit-policy"]
token_meta_role      admin-users
token_meta_username  admin@company.com
```

## 🔧 Configuration Reference

### Server Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `imap_server` | string | - | **Required.** IMAP server hostname |
| `imap_port` | integer | `993` | IMAP server port |
| `imap_ssl` | boolean | `true` | Use SSL/TLS (IMAPS) |
| `use_starttls` | boolean | `false` | Use STARTTLS upgrade |
| `skip_tls_verify` | boolean | `false` | Skip certificate verification |
| `connection_timeout` | duration | `30s` | Connection timeout |
| `secure_nonce` | boolean | `false` | Require nonce validation |

### Role Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `principals` | []string | - | Email patterns (regex supported) |
| `token_ttl` | duration | `0` | Token TTL |
| `token_max_ttl` | duration | `0` | Maximum token TTL |
| `token_policies` | []string | - | Policies to assign |
| `token_bound_cidrs` | []string | - | IP address restrictions |
| `token_explicit_max_ttl` | duration | `0` | Explicit maximum TTL |
| `token_no_default_policy` | boolean | `false` | Don't assign default policy |
| `token_num_uses` | integer | `0` | Token use limit |
| `token_period` | duration | `0` | Token renewal period |
| `token_type` | string | `default` | Token type |

## 🔒 Security Features

This plugin includes enterprise-grade security features:

### Input Validation & Sanitization
- Comprehensive input validation for all parameters
- Protection against injection attacks
- Configurable length limits for usernames and passwords

### ReDoS Protection
- Timeout controls for regex pattern matching
- Prevention of catastrophic backtracking attacks
- Safe handling of complex regex patterns

### Connection Security
- Full TLS/SSL support with certificate validation
- STARTTLS upgrade support for legacy servers
- Configurable connection timeouts
- Protection against connection exhaustion

### Secure Nonce Support
- Optional cryptographic nonce validation
- Time-based nonce expiration
- Base64 encoding with proper validation

### Network Security
- IP-based access restrictions (CIDR support)
- Connection source validation
- Proper error message sanitization

## 🏗️ Development

### Prerequisites

- [Go](https://golang.org) 1.24+ installed
- [HashiCorp Vault](https://www.vaultproject.io/) for testing
- [Docker](https://docker.com) (optional, for test environment)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/mabunixda/vault-plugin-auth-imap.git
cd vault-plugin-auth-imap

# Build the plugin
make build

# The binary will be available in ./dist/
```

### Development Setup

```bash
# Start a development Vault instance with the plugin
make dev

# In another terminal, enable the plugin
vault auth enable -path=imap vault-plugin-auth-imap
```

### Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run specific tests
cd internal/imapauth
go test -v -run TestSpecificFunction

# Run integration tests (requires IMAP server)
make test-integration
```

### Test Environment Setup

The plugin includes scripts for setting up a test environment:

```bash
# Setup test environment (see scripts/devsetup.sh)
export MAILSERVER="imap.example.com"
./scripts/devsetup.sh

# Start local development vault
make start
```

## 📋 API Reference

### Configuration Endpoint: `auth/imap/config`

**Write Configuration:**
```bash
vault write auth/imap/config [parameters...]
```

**Read Configuration:**
```bash
vault read auth/imap/config
```

### Role Management: `auth/imap/role/<role-name>`

**Create/Update Role:**
```bash
vault write auth/imap/role/<role-name> [parameters...]
```

**Read Role:**
```bash
vault read auth/imap/role/<role-name>
```

**Delete Role:**
```bash
vault delete auth/imap/role/<role-name>
```

**List Roles:**
```bash
vault list auth/imap/role
```

### Authentication: `auth/imap/login`

**Login:**
```bash
vault write auth/imap/login role=<role-name> username=<email> password=<password> [nonce=<nonce>]
```

### Nonce Management: `auth/imap/nonce`

**Generate Nonce (if secure_nonce enabled):**
```bash
vault read auth/imap/nonce
```

## 🚀 Production Deployment

### Installation

1. **Download the latest release:**
   ```bash
   wget https://github.com/mabunixda/vault-plugin-auth-imap/releases/download/v1.3.0/vault-plugin-auth-imap-linux-amd64
   ```

2. **Install to Vault plugins directory:**
   ```bash
   sudo cp vault-plugin-auth-imap-linux-amd64 /opt/vault/plugins/
   sudo chmod +x /opt/vault/plugins/vault-plugin-auth-imap-linux-amd64
   ```

3. **Register with Vault:**
   ```bash
   vault plugin register -sha256=$(sha256sum /opt/vault/plugins/vault-plugin-auth-imap-linux-amd64 | cut -d' ' -f1) auth vault-plugin-auth-imap
   ```

4. **Enable the plugin:**
   ```bash
   vault auth enable -path=imap vault-plugin-auth-imap
   ```

### Best Practices

- 🔒 **Always use TLS/SSL** in production environments
- 🎯 **Use specific principal patterns** rather than allowing all users
- ⏱️ **Set appropriate token TTLs** for your security requirements
- 🌐 **Use CIDR restrictions** for network-based access control
- 🔐 **Enable secure nonce** for high-security environments
- 📊 **Monitor authentication logs** for unusual activity
- 🔄 **Regularly rotate IMAP service account passwords** if using dedicated accounts

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Process

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure all tests pass
5. Submit a pull request

### Code Quality

- All code must pass `golangci-lint` checks
- Maintain test coverage above 70%
- Follow Go best practices and conventions
- Sign your commits with GPG

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📚 **Documentation**: Check this README and inline code comments
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/mabunixda/vault-plugin-auth-imap/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/mabunixda/vault-plugin-auth-imap/discussions)
- 📧 **Security Issues**: Please report privately to the maintainers

## 🔗 Related Projects

- [HashiCorp Vault](https://www.vaultproject.io/) - The secret management platform this plugin extends
- [Vault Plugin Registry](https://www.vaultproject.io/docs/internals/plugins) - Official documentation on Vault plugins

---

**Version**: v1.3.0 | **Go Version**: 1.24+ | **Vault Compatibility**: 1.12+
