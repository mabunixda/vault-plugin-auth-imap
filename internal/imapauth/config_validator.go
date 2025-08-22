package imapauth

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// ConfigValidator handles validation of configuration entries
type ConfigValidator struct{}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{}
}

// ValidateConfig validates a complete configuration entry
func (cv *ConfigValidator) ValidateConfig(config *ConfigEntry) error {
	if err := cv.ValidateServer(config.ImapServer); err != nil {
		return err
	}

	if err := cv.ValidatePort(config.ImapPort); err != nil {
		return err
	}

	if err := cv.ValidateTimeouts(config.ConnectionTimeout); err != nil {
		return err
	}

	if err := cv.ValidateTLSConfig(config.ImapSsl, config.StartTLS); err != nil {
		return err
	}

	return nil
}

// ValidateServer validates the IMAP server address
func (cv *ConfigValidator) ValidateServer(server string) error {
	if server == "" {
		return fmt.Errorf("imap_server is required")
	}

	// Trim whitespace
	server = strings.TrimSpace(server)
	if server == "" {
		return fmt.Errorf("imap_server cannot be empty or whitespace only")
	}

	// Check if it's a valid hostname or IP
	if net.ParseIP(server) == nil {
		// If not an IP, validate as hostname
		if len(server) > 253 {
			return fmt.Errorf("hostname too long (max 253 characters)")
		}

		// Basic hostname validation
		if strings.Contains(server, "..") || strings.HasPrefix(server, ".") || strings.HasSuffix(server, ".") {
			return fmt.Errorf("invalid hostname format")
		}
	}

	return nil
}

// ValidatePort validates the IMAP server port
func (cv *ConfigValidator) ValidatePort(port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port number: %d (must be 1-65535)", port)
	}
	return nil
}

// ValidateTimeouts validates timeout configurations
func (cv *ConfigValidator) ValidateTimeouts(connectionTimeout time.Duration) error {
	if connectionTimeout < time.Second {
		return fmt.Errorf("connection_timeout too short (minimum 1 second)")
	}

	if connectionTimeout > 5*time.Minute {
		return fmt.Errorf("connection_timeout too long (maximum 5 minutes)")
	}

	return nil
}

// ValidateTLSConfig validates TLS configuration options
func (cv *ConfigValidator) ValidateTLSConfig(imapSsl, startTLS bool) error {
	if imapSsl && startTLS {
		return fmt.Errorf("cannot enable both imap_ssl and starttls simultaneously")
	}
	return nil
}

// SanitizeAndNormalize sanitizes and normalizes configuration values
func (cv *ConfigValidator) SanitizeAndNormalize(config *ConfigEntry) {
	// Normalize server address
	config.ImapServer = strings.TrimSpace(config.ImapServer)
	config.ImapServer = strings.ToLower(config.ImapServer)

	// Set default timeout if not specified
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = DefaultConnectionTimeout
	}

	// Ensure sensible defaults for security
	if config.ImapPort == 0 {
		if config.ImapSsl {
			config.ImapPort = 993 // Standard IMAPS port
		} else {
			config.ImapPort = 143 // Standard IMAP port
		}
	}
}

// GetConnectionString returns a formatted connection string for logging
func (cv *ConfigValidator) GetConnectionString(config *ConfigEntry) string {
	protocol := "IMAP"
	if config.ImapSsl {
		protocol = "IMAPS"
	} else if config.StartTLS {
		protocol = "IMAP+STARTTLS"
	}

	return fmt.Sprintf("%s://%s:%d", protocol, config.ImapServer, config.ImapPort)
}
