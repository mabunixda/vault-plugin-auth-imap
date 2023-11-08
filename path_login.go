package imapauth

import (
	"context"
	"encoding/base64"
	"fmt"
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

	// if we have explicit principals we must check those
	if len(role.Principals) > 0 && !slices.Contains(role.Principals, principal) {
		return logical.ErrorResponse("invalid username"), nil
	}

	var imapClient *client.Client
	imapServer := fmt.Sprintf("%s:%d", config.ImapServer, config.ImapPort)

	if config.ImapSsl {
		imapClient, err = client.DialTLS(imapServer, nil)
	} else {
		imapClient, err = client.Dial(imapServer)
	}
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Could not connect to mailserver, %s ", err)), err
	}

	defer imapClient.Logout() //nolint:all

	if err := imapClient.Login(principal, password); err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Could not login '%s' to '%s' - %s ", principal, imapServer, err)), err
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

func validNonceTime(nonce []byte) bool {
	t := time.Time{}
	_ = t.UnmarshalBinary(nonce)

	return time.Since(t) <= time.Second*30
}
