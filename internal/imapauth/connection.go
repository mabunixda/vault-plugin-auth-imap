package imapauth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/emersion/go-imap/client"
	"github.com/hashicorp/go-hclog"
)

// IMAPConnectionManager handles IMAP connection establishment and management
type IMAPConnectionManager struct {
	config *ConfigEntry
	logger hclog.Logger
}

// NewIMAPConnectionManager creates a new IMAP connection manager
func NewIMAPConnectionManager(config *ConfigEntry, logger hclog.Logger) *IMAPConnectionManager {
	return &IMAPConnectionManager{
		config: config,
		logger: logger,
	}
}

// EstablishConnection creates and returns an IMAP client connection
func (icm *IMAPConnectionManager) EstablishConnection(ctx context.Context) (*client.Client, error) {
	if icm.config == nil {
		return nil, ErrConfigurationNil
	}

	imapServer := fmt.Sprintf("%s:%d", icm.config.ImapServer, icm.config.ImapPort)

	// Setup connection with timeout
	dialer := &net.Dialer{
		Timeout: icm.config.ConnectionTimeout,
	}

	// Add context deadline if provided
	if deadline, ok := ctx.Deadline(); ok {
		remainingTime := time.Until(deadline)
		if remainingTime < dialer.Timeout {
			dialer.Timeout = remainingTime
		}
	}

	connType := icm.determineConnectionType()
	icm.logger.Debug("establishing IMAP connection",
		"server", icm.config.ImapServer,
		"port", icm.config.ImapPort,
		"type", connType.String())

	switch connType {
	case ConnectionTLS:
		return icm.establishTLSConnection(dialer, imapServer)
	case ConnectionStartTLS:
		return icm.establishStartTLSConnection(dialer, imapServer)
	default:
		return icm.establishPlainConnection(dialer, imapServer)
	}
}

// determineConnectionType determines the appropriate connection type based on configuration
func (icm *IMAPConnectionManager) determineConnectionType() ConnectionType {
	if icm.config.ImapSsl {
		return ConnectionTLS
	}
	if icm.config.StartTLS {
		return ConnectionStartTLS
	}
	return ConnectionPlain
}

// establishTLSConnection creates a direct TLS connection
func (icm *IMAPConnectionManager) establishTLSConnection(dialer *net.Dialer, server string) (*client.Client, error) {
	tlsConfig := &tls.Config{
		ServerName:         icm.config.ImapServer,
		InsecureSkipVerify: icm.config.SkipTLSVerify,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", server, tlsConfig)
	if err != nil {
		icm.logger.Error(LogMsgIMAPTLSFailed, "error", err, "server", server)
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	imapClient, err := client.New(conn)
	if err != nil {
		_ = conn.Close()
		icm.logger.Error(LogMsgIMAPClientFailed, "error", err)
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	return imapClient, nil
}

// establishStartTLSConnection creates a plain connection and upgrades to TLS
func (icm *IMAPConnectionManager) establishStartTLSConnection(dialer *net.Dialer, server string) (*client.Client, error) {
	// First establish plain connection
	imapClient, err := icm.establishPlainConnection(dialer, server)
	if err != nil {
		return nil, err
	}

	// Upgrade to TLS
	tlsConfig := &tls.Config{
		ServerName:         icm.config.ImapServer,
		InsecureSkipVerify: icm.config.SkipTLSVerify,
	}

	if err := imapClient.StartTLS(tlsConfig); err != nil {
		_ = imapClient.Logout()
		icm.logger.Error(LogMsgStartTLSFailed, "error", err)
		return nil, fmt.Errorf("%w: STARTTLS failed: %v", ErrConnectionFailed, err)
	}

	return imapClient, nil
}

// establishPlainConnection creates a plain TCP connection
func (icm *IMAPConnectionManager) establishPlainConnection(dialer *net.Dialer, server string) (*client.Client, error) {
	conn, err := dialer.Dial("tcp", server)
	if err != nil {
		icm.logger.Error(LogMsgIMAPConnectFailed, "error", err, "server", server)
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	imapClient, err := client.New(conn)
	if err != nil {
		_ = conn.Close()
		icm.logger.Error(LogMsgIMAPClientFailed, "error", err)
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	return imapClient, nil
}

// AuthenticateUser attempts to authenticate a user against the IMAP server
func (icm *IMAPConnectionManager) AuthenticateUser(ctx context.Context, username, password string) error {
	imapClient, err := icm.EstablishConnection(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if imapClient != nil {
			if logoutErr := imapClient.Logout(); logoutErr != nil {
				icm.logger.Warn("failed to logout from IMAP server", "error", logoutErr)
			}
		}
	}()

	if err := imapClient.Login(username, password); err != nil {
		icm.logger.Warn(LogMsgAuthFailed, "username", username, "error", err)
		return fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
	}

	icm.logger.Debug("IMAP authentication successful", "username", username)
	return nil
}
