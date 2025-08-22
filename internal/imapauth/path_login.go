package imapauth

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"slices"
	"time"

	"github.com/emersion/go-imap/client"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Role to use",
			},
			"password": {
				Type:        framework.TypeString,
				Description: "FIXXME",
			},
			"username": {
				Type:        framework.TypeString,
				Description: "FIXXME",
			},
			"nonce": {
				Type:        framework.TypeString,
				Description: "Nonce (base64 encoded)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleLogin,
				Summary:  "Log in using imap authentication",
			},
			logical.AliasLookaheadOperation: &framework.PathOperation{
				Callback: b.handleLogin,
			},
		},
	}
}

func (b *backend) handleLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return logical.ErrorResponse("could not load configuration"), nil
	}

	roleName := data.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("role must be provided"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse("role %q could not be found", roleName), nil
	}

	if len(role.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}

		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, role.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	nonce := data.Get("nonce").(string)
	if config.SecureNonce {
		if nonce == "" {
			return logical.ErrorResponse("nonce must be provided"), nil
		}

		nonceDecode, err := base64.StdEncoding.DecodeString(nonce)
		if err != nil {
			return logical.ErrorResponse("decoding nonce failed"), nil
		}

		if !b.nonceValidate(config, nonceDecode) {
			return logical.ErrorResponse("nonce time expired or invalid"), nil
		}
	}
	// Name for the logical.Alias to set
	aliasName := roleName //nolint:all

	principal := data.Get("username").(string)
	password := data.Get("password").(string)

	// Input validation
	if principal == "" {
		return logical.ErrorResponse("username is required"), nil
	}
	if password == "" {
		return logical.ErrorResponse("password is required"), nil
	}

	// Sanitize principal to prevent injection attacks
	if len(principal) > 256 {
		return logical.ErrorResponse("username too long"), nil
	}
	if len(password) > 256 {
		return logical.ErrorResponse("password too long"), nil
	}

	// if we have explicit principals we must check those
	if !b.isValidPrincipal(role.Principals, principal) {
		return logical.ErrorResponse("invalid username"), nil
	}

	var imapClient *client.Client
	imapServer := fmt.Sprintf("%s:%d", config.ImapServer, config.ImapPort)

	// Setup connection with timeout
	dialer := &net.Dialer{
		Timeout: config.ConnectionTimeout,
	}

	if config.ImapSsl {
		// Direct TLS connection
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.SkipTLSVerify,
		}
		conn, err := tls.DialWithDialer(dialer, "tcp", imapServer, tlsConfig)
		if err != nil {
			b.Logger().Error("Failed to establish TLS connection to IMAP server", "error", err)
			return logical.ErrorResponse("Authentication failed"), nil
		}
		imapClient, err = client.New(conn)
		if err != nil {
			_ = conn.Close()
			b.Logger().Error("Failed to create IMAP client", "error", err)
			return logical.ErrorResponse("Authentication failed"), nil
		}
	} else {
		// Plain connection, potentially with STARTTLS
		conn, err := dialer.Dial("tcp", imapServer)
		if err != nil {
			b.Logger().Error("Failed to connect to IMAP server", "error", err)
			return logical.ErrorResponse("Authentication failed"), nil
		}
		imapClient, err = client.New(conn)
		if err != nil {
			_ = conn.Close()
			b.Logger().Error("Failed to create IMAP client", "error", err)
			return logical.ErrorResponse("Authentication failed"), nil
		}

		// If STARTTLS is enabled, attempt to upgrade the connection
		if config.StartTLS {
			tlsConfig := &tls.Config{
				ServerName:         config.ImapServer,
				InsecureSkipVerify: config.SkipTLSVerify,
			}
			if err := imapClient.StartTLS(tlsConfig); err != nil {
				b.Logger().Error("STARTTLS failed", "error", err)
				return logical.ErrorResponse("Authentication failed"), nil
			}
		}
	}

	defer func() {
		if imapClient != nil {
			_ = imapClient.Logout()
		}
	}()

	if err := imapClient.Login(principal, password); err != nil {
		b.Logger().Warn("IMAP authentication failed", "principal", principal, "error", err)
		return logical.ErrorResponse("Authentication failed"), nil
	}
	// Take the principal as the alias name
	aliasName = principal

	metadata := map[string]string{}
	if metadataRaw, ok := data.GetOk("metadata"); ok {
		for key, value := range metadataRaw.(map[string]string) {
			metadata[key] = value
		}
	}
	// Set role last in case need to override something user set
	metadata["role"] = roleName

	// Compose the response
	resp := &logical.Response{}
	auth := &logical.Auth{
		InternalData: map[string]interface{}{
			"role": roleName,
		},
		Metadata:    metadata,
		DisplayName: aliasName,
		Alias: &logical.Alias{
			Name:     aliasName,
			Metadata: metadata,
		},
	}

	role.PopulateTokenAuth(auth)

	resp.Auth = auth

	return resp, nil
}

func (b *backend) isValidPrincipal(principals []string, principal string) bool {
	// either no principals configured
	if len(principals) == 0 {
		return true
	}

	// Sanitize principal
	if len(principal) == 0 || len(principal) > 256 {
		return false
	}

	// ... or the principal is in the list as string
	if slices.Contains(principals, principal) {
		return true
	}

	b.Logger().Debug("principal not in list - checking regex patterns")
	for _, p := range principals {
		// Limit regex pattern length to prevent ReDoS
		if len(p) > 1000 {
			b.Logger().Warn("skipping overly long regex pattern")
			continue
		}

		re, err := regexp.Compile(p)
		if err != nil {
			b.Logger().Warn("invalid regex pattern", "pattern", p, "error", err)
			continue
		}

		// Set a timeout for regex execution to prevent ReDoS
		matched := make(chan bool, 1)
		go func() {
			matched <- re.MatchString(principal)
		}()

		select {
		case result := <-matched:
			if result {
				return true
			}
		case <-time.After(100 * time.Millisecond):
			b.Logger().Warn("regex pattern timed out", "pattern", p)
			continue
		}
	}
	return false
}

func validNonceTime(nonce []byte) bool {
	t := time.Time{}
	_ = t.UnmarshalBinary(nonce)

	return time.Since(t) <= time.Second*30
}
