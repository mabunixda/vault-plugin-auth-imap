package imapauth

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathConfig() *framework.Path {
	p := &framework.Path{
		Pattern: `config`,
		Fields: map[string]*framework.FieldSchema{
			"imap_server": {
				Type:        framework.TypeString,
				Description: `IMAP server address(es).`,
			},
			"imap_port": {
				Type:        framework.TypeInt,
				Description: `IMAP server port.`,
				Default:     993,
			},
			"imap_ssl": {
				Type:        framework.TypeBool,
				Description: `Whether to use SSL when connecting to the IMAP server.`,
				Default:     true,
			},
			"secure_nonce": {
				Type:        framework.TypeBool,
				Description: `Whether to use secure nonce generation.`,
				Default:     false,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				Summary:  "Read the current IMAP authentication backend configuration.",
			},

			logical.UpdateOperation: &framework.PathOperation{
				Callback:    b.pathConfigWrite,
				Summary:     "Configure the IMAP authentication backend.",
				Description: confHelpDesc,
			},
		},

		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}

	tokenutil.AddTokenFields(p.Fields)

	return p
}

func (b *backend) config(ctx context.Context, s logical.Storage) (*ConfigEntry, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := &ConfigEntry{}

	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}

	return config, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	d := map[string]interface{}{
		"imap_server":  config.ImapServer,
		"imap_port":    config.ImapPort,
		"imap_ssl":     config.ImapSsl,
		"secure_nonce": config.SecureNonce,
	}

	config.PopulateTokenData(d)

	return &logical.Response{
		Data: d,
	}, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config := &ConfigEntry{
		ImapServer:  d.Get("imap_server").(string),
		ImapPort:    d.Get("imap_port").(int),
		ImapSsl:     d.Get("imap_ssl").(bool),
		SecureNonce: d.Get("secure_nonce").(bool),
	}

	if err := config.ParseTokenFields(req, d); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

const (
	confHelpSyn = `
Configures the IMAP authentication backend.
`
	confHelpDesc = `
The IMAP authentication backend validates imap credentials.
`
)
