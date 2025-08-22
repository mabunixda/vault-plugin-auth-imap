package imapauth

import (
	"errors"
	"time"
)

// Constants for configuration limits and defaults
const (
	// Input validation limits
	MaxUsernameLength = 256
	MaxPasswordLength = 256
	MaxRegexLength    = 1000

	// Timeout configurations
	DefaultConnectionTimeout = 30 * time.Second
	DefaultNonceTimeout      = 30 * time.Second
	RegexExecutionTimeout    = 100 * time.Millisecond

	// Field descriptions
	UsernameFieldDesc = "Username for IMAP authentication"
	PasswordFieldDesc = "Password for IMAP authentication"
	NonceFieldDesc    = "Base64 encoded nonce for secure authentication"
	RoleFieldDesc     = "Role name to authenticate against"

	// Error messages
	ErrMsgConfigNotFound    = "could not load configuration"
	ErrMsgRoleRequired      = "role must be provided"
	ErrMsgRoleNotFound      = "role could not be found"
	ErrMsgUsernameRequired  = "username is required"
	ErrMsgPasswordRequired  = "password is required"
	ErrMsgUsernameTooLong   = "username too long"
	ErrMsgPasswordTooLong   = "password too long"
	ErrMsgInvalidUsername   = "invalid username"
	ErrMsgNonceRequired     = "nonce must be provided"
	ErrMsgNonceDecodeFailed = "decoding nonce failed"
	ErrMsgNonceInvalid      = "nonce time expired or invalid"
	ErrMsgAuthFailed        = "Authentication failed"

	// Log messages
	LogMsgIMAPConnectFailed  = "Failed to connect to IMAP server"
	LogMsgIMAPTLSFailed      = "Failed to establish TLS connection to IMAP server"
	LogMsgIMAPClientFailed   = "Failed to create IMAP client"
	LogMsgStartTLSFailed     = "STARTTLS failed"
	LogMsgAuthFailed         = "IMAP authentication failed"
	LogMsgRegexTimeout       = "regex pattern timed out"
	LogMsgRegexInvalid       = "invalid regex pattern"
	LogMsgRegexTooLong       = "skipping overly long regex pattern"
	LogMsgCIDRValidationWarn = "token bound CIDRs found but no connection information available for validation"
)

// Custom errors for better error handling
var (
	ErrConfigurationNil     = errors.New("configuration is nil")
	ErrRoleNotFound         = errors.New("role not found")
	ErrInvalidInput         = errors.New("invalid input provided")
	ErrConnectionFailed     = errors.New("failed to establish connection")
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrNonceValidation      = errors.New("nonce validation failed")
)

// ConnectionType represents the type of IMAP connection
type ConnectionType int

const (
	ConnectionPlain ConnectionType = iota
	ConnectionTLS
	ConnectionStartTLS
)

// String returns a string representation of the connection type
func (ct ConnectionType) String() string {
	switch ct {
	case ConnectionPlain:
		return "plain"
	case ConnectionTLS:
		return "tls"
	case ConnectionStartTLS:
		return "starttls"
	default:
		return "unknown"
	}
}
