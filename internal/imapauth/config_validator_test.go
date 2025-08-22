package imapauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewConfigValidator(t *testing.T) {
	validator := NewConfigValidator()
	assert.NotNil(t, validator)
}

func TestConfigValidator_ValidateConfig(t *testing.T) {
	validator := NewConfigValidator()

	tests := []struct {
		name        string
		config      *ConfigEntry
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &ConfigEntry{
				ImapServer:        "mail.example.com",
				ImapPort:          993,
				ConnectionTimeout: 30 * time.Second,
				ImapSsl:           true,
				StartTLS:          false,
			},
			expectError: false,
		},
		{
			name: "invalid server",
			config: &ConfigEntry{
				ImapServer:        "",
				ImapPort:          993,
				ConnectionTimeout: 30 * time.Second,
			},
			expectError: true,
			errorMsg:    "imap_server is required",
		},
		{
			name: "invalid port",
			config: &ConfigEntry{
				ImapServer:        "mail.example.com",
				ImapPort:          0,
				ConnectionTimeout: 30 * time.Second,
			},
			expectError: true,
			errorMsg:    "invalid port number",
		},
		{
			name: "invalid timeout",
			config: &ConfigEntry{
				ImapServer:        "mail.example.com",
				ImapPort:          993,
				ConnectionTimeout: 500 * time.Millisecond,
			},
			expectError: true,
			errorMsg:    "connection_timeout too short",
		},
		{
			name: "conflicting TLS config",
			config: &ConfigEntry{
				ImapServer:        "mail.example.com",
				ImapPort:          993,
				ConnectionTimeout: 30 * time.Second,
				ImapSsl:           true,
				StartTLS:          true,
			},
			expectError: true,
			errorMsg:    "cannot enable both imap_ssl and starttls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateConfig(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigValidator_ValidateServer(t *testing.T) {
	validator := NewConfigValidator()

	tests := []struct {
		name        string
		server      string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid hostname",
			server:      "mail.example.com",
			expectError: false,
		},
		{
			name:        "valid IP address",
			server:      "192.168.1.1",
			expectError: false,
		},
		{
			name:        "valid IPv6 address",
			server:      "2001:db8::1",
			expectError: false,
		},
		{
			name:        "empty server",
			server:      "",
			expectError: true,
			errorMsg:    "imap_server is required",
		},
		{
			name:        "whitespace only server",
			server:      "   ",
			expectError: true,
			errorMsg:    "imap_server cannot be empty or whitespace only",
		},
		{
			name:        "hostname too long",
			server:      string(make([]byte, 254)), // 254 characters, over limit
			expectError: true,
			errorMsg:    "hostname too long",
		},
		{
			name:        "hostname with double dots",
			server:      "mail..example.com",
			expectError: true,
			errorMsg:    "invalid hostname format",
		},
		{
			name:        "hostname starting with dot",
			server:      ".example.com",
			expectError: true,
			errorMsg:    "invalid hostname format",
		},
		{
			name:        "hostname ending with dot",
			server:      "example.com.",
			expectError: true,
			errorMsg:    "invalid hostname format",
		},
		{
			name:        "valid hostname at length limit",
			server:      string(make([]byte, 253)), // Exactly at limit
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateServer(tt.server)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigValidator_ValidatePort(t *testing.T) {
	validator := NewConfigValidator()

	tests := []struct {
		name        string
		port        int
		expectError bool
	}{
		{name: "valid port 993", port: 993, expectError: false},
		{name: "valid port 143", port: 143, expectError: false},
		{name: "valid port 1", port: 1, expectError: false},
		{name: "valid port 65535", port: 65535, expectError: false},
		{name: "invalid port 0", port: 0, expectError: true},
		{name: "invalid port -1", port: -1, expectError: true},
		{name: "invalid port 65536", port: 65536, expectError: true},
		{name: "invalid port 100000", port: 100000, expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePort(tt.port)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid port number")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigValidator_ValidateTimeouts(t *testing.T) {
	validator := NewConfigValidator()

	tests := []struct {
		name        string
		timeout     time.Duration
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid timeout 30s",
			timeout:     30 * time.Second,
			expectError: false,
		},
		{
			name:        "valid timeout 1s",
			timeout:     1 * time.Second,
			expectError: false,
		},
		{
			name:        "valid timeout 5m",
			timeout:     5 * time.Minute,
			expectError: false,
		},
		{
			name:        "timeout too short",
			timeout:     500 * time.Millisecond,
			expectError: true,
			errorMsg:    "connection_timeout too short",
		},
		{
			name:        "timeout too long",
			timeout:     6 * time.Minute,
			expectError: true,
			errorMsg:    "connection_timeout too long",
		},
		{
			name:        "zero timeout",
			timeout:     0,
			expectError: true,
			errorMsg:    "connection_timeout too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateTimeouts(tt.timeout)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigValidator_ValidateTLSConfig(t *testing.T) {
	validator := NewConfigValidator()

	tests := []struct {
		name        string
		imapSsl     bool
		startTLS    bool
		expectError bool
	}{
		{name: "SSL only", imapSsl: true, startTLS: false, expectError: false},
		{name: "STARTTLS only", imapSsl: false, startTLS: true, expectError: false},
		{name: "neither", imapSsl: false, startTLS: false, expectError: false},
		{name: "both (conflict)", imapSsl: true, startTLS: true, expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateTLSConfig(tt.imapSsl, tt.startTLS)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "cannot enable both imap_ssl and starttls")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigValidator_SanitizeAndNormalize(t *testing.T) {
	validator := NewConfigValidator()

	tests := []struct {
		name            string
		input           *ConfigEntry
		expectedServer  string
		expectedPort    int
		expectedTimeout time.Duration
	}{
		{
			name: "trim and lowercase server",
			input: &ConfigEntry{
				ImapServer: "  MAIL.EXAMPLE.COM  ",
				ImapPort:   993,
			},
			expectedServer:  "mail.example.com",
			expectedPort:    993,
			expectedTimeout: DefaultConnectionTimeout,
		},
		{
			name: "set default port for SSL",
			input: &ConfigEntry{
				ImapServer: "mail.example.com",
				ImapPort:   0,
				ImapSsl:    true,
			},
			expectedServer:  "mail.example.com",
			expectedPort:    993,
			expectedTimeout: DefaultConnectionTimeout,
		},
		{
			name: "set default port for non-SSL",
			input: &ConfigEntry{
				ImapServer: "mail.example.com",
				ImapPort:   0,
				ImapSsl:    false,
			},
			expectedServer:  "mail.example.com",
			expectedPort:    143,
			expectedTimeout: DefaultConnectionTimeout,
		},
		{
			name: "preserve existing timeout",
			input: &ConfigEntry{
				ImapServer:        "mail.example.com",
				ImapPort:          993,
				ConnectionTimeout: 60 * time.Second,
			},
			expectedServer:  "mail.example.com",
			expectedPort:    993,
			expectedTimeout: 60 * time.Second,
		},
		{
			name: "set default timeout when zero",
			input: &ConfigEntry{
				ImapServer:        "mail.example.com",
				ImapPort:          993,
				ConnectionTimeout: 0,
			},
			expectedServer:  "mail.example.com",
			expectedPort:    993,
			expectedTimeout: DefaultConnectionTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator.SanitizeAndNormalize(tt.input)

			assert.Equal(t, tt.expectedServer, tt.input.ImapServer)
			assert.Equal(t, tt.expectedPort, tt.input.ImapPort)
			assert.Equal(t, tt.expectedTimeout, tt.input.ConnectionTimeout)
		})
	}
}

func TestConfigValidator_GetConnectionString(t *testing.T) {
	validator := NewConfigValidator()

	tests := []struct {
		name     string
		config   *ConfigEntry
		expected string
	}{
		{
			name: "IMAPS connection",
			config: &ConfigEntry{
				ImapServer: "mail.example.com",
				ImapPort:   993,
				ImapSsl:    true,
				StartTLS:   false,
			},
			expected: "IMAPS://mail.example.com:993",
		},
		{
			name: "IMAP with STARTTLS",
			config: &ConfigEntry{
				ImapServer: "mail.example.com",
				ImapPort:   143,
				ImapSsl:    false,
				StartTLS:   true,
			},
			expected: "IMAP+STARTTLS://mail.example.com:143",
		},
		{
			name: "Plain IMAP connection",
			config: &ConfigEntry{
				ImapServer: "mail.example.com",
				ImapPort:   143,
				ImapSsl:    false,
				StartTLS:   false,
			},
			expected: "IMAP://mail.example.com:143",
		},
		{
			name: "IMAPS takes precedence over STARTTLS",
			config: &ConfigEntry{
				ImapServer: "mail.example.com",
				ImapPort:   993,
				ImapSsl:    true,
				StartTLS:   true,
			},
			expected: "IMAPS://mail.example.com:993",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.GetConnectionString(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}
