package imapauth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

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
				Description: RoleFieldDesc,
			},
			"password": {
				Type:        framework.TypeString,
				Description: PasswordFieldDesc,
			},
			"username": {
				Type:        framework.TypeString,
				Description: UsernameFieldDesc,
			},
			"nonce": {
				Type:        framework.TypeString,
				Description: NonceFieldDesc,
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
	// Load configuration
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse(ErrMsgConfigNotFound), nil
	}

	// Extract and validate basic input data (but not nonce yet)
	loginData, err := b.extractLoginData(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Validate basic input (role, username, password) but not nonce
	validator := NewInputValidator(b.Logger())
	if err := validator.ValidateRole(loginData.Role); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if err := validator.ValidateCredentials(loginData.Username, loginData.Password); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Load and validate role (this should come before nonce validation to match test expectations)
	role, err := b.loadAndValidateRole(ctx, req, loginData.Role)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role %q could not be found", loginData.Role)), nil
	}

	// Validate nonce if secure nonce is enabled (after role validation)
	if config.SecureNonce {
		if err := validator.ValidateNonce(loginData.Nonce); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		if err := b.validateSecureNonce(config, loginData.Nonce); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
	}

	// Validate principal against role
	principalValidator := NewPrincipalValidator(b.Logger())
	if !principalValidator.ValidatePrincipal(role.Principals, loginData.Username) {
		return logical.ErrorResponse(ErrMsgInvalidUsername), nil
	}

	// Authenticate with IMAP server
	connManager := NewIMAPConnectionManager(config, b.Logger())
	if err := connManager.AuthenticateUser(ctx, loginData.Username, loginData.Password); err != nil {
		return logical.ErrorResponse(ErrMsgAuthFailed), nil
	}

	// Build successful response
	return b.buildAuthResponse(loginData, role)
}

// LoginData holds the extracted login data from the request
type LoginData struct {
	Role     string
	Username string
	Password string
	Nonce    string
}

// extractLoginData extracts and returns login data from the request
func (b *backend) extractLoginData(data *framework.FieldData) (*LoginData, error) {
	role, ok := data.GetOk("role")
	if !ok || role == nil {
		return nil, errors.New(ErrMsgRoleRequired)
	}

	username, ok := data.GetOk("username")
	if !ok || username == nil {
		return nil, errors.New(ErrMsgUsernameRequired)
	}

	password, ok := data.GetOk("password")
	if !ok || password == nil {
		return nil, errors.New(ErrMsgPasswordRequired)
	}

	nonce, _ := data.GetOk("nonce") // nonce is optional

	var nonceStr string
	if nonce != nil {
		nonceStr = nonce.(string)
	}

	return &LoginData{
		Role:     role.(string),
		Username: username.(string),
		Password: password.(string),
		Nonce:    nonceStr,
	}, nil
}

// loadAndValidateRole loads a role and validates CIDR restrictions
func (b *backend) loadAndValidateRole(ctx context.Context, req *logical.Request, roleName string) (*imapRole, error) {
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role != nil && len(role.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn(LogMsgCIDRValidationWarn)
			return nil, logical.ErrPermissionDenied
		}

		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, role.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	return role, nil
}

// validateSecureNonce validates a nonce when secure nonce is enabled
func (b *backend) validateSecureNonce(config *ConfigEntry, nonce string) error {
	if nonce == "" {
		return errors.New(ErrMsgNonceRequired)
	}

	nonceDecode, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return errors.New(ErrMsgNonceDecodeFailed)
	}

	if !b.nonceValidate(config, nonceDecode) {
		return errors.New(ErrMsgNonceInvalid)
	}

	return nil
}

// buildAuthResponse builds the authentication response
func (b *backend) buildAuthResponse(loginData *LoginData, role *imapRole) (*logical.Response, error) {
	aliasName := loginData.Username

	metadata := map[string]string{
		"role": loginData.Role,
	}

	auth := &logical.Auth{
		InternalData: map[string]interface{}{
			"role": loginData.Role,
		},
		Metadata:    metadata,
		DisplayName: aliasName,
		Alias: &logical.Alias{
			Name:     aliasName,
			Metadata: metadata,
		},
	}

	role.PopulateTokenAuth(auth)

	return &logical.Response{
		Auth: auth,
	}, nil
}

func (b *backend) isValidPrincipal(principals []string, principal string) bool {
	validator := NewPrincipalValidator(b.Logger())
	return validator.ValidatePrincipal(principals, principal)
}

func validNonceTime(nonce []byte) bool {
	t := time.Time{}
	_ = t.UnmarshalBinary(nonce)

	return time.Since(t) <= time.Second*30
}
