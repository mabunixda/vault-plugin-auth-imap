package imapauth

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateSecureNonce(t *testing.T) {
	b, _ := getTestBackend(t)

	// Setup a valid config with secure nonce enabled
	config := &ConfigEntry{
		ImapServer:        "localhost",
		ImapPort:          993,
		ImapSsl:           true,
		ConnectionTimeout: 30 * time.Second,
		SecureNonce:       true,
	}

	tests := []struct {
		name        string
		nonce       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty nonce",
			nonce:       "",
			expectError: true,
			errorMsg:    ErrMsgNonceRequired,
		},
		{
			name:        "invalid base64 nonce",
			nonce:       "invalid-base64!!!",
			expectError: true,
			errorMsg:    ErrMsgNonceDecodeFailed,
		},
		{
			name:        "valid base64 but invalid nonce",
			nonce:       "dGVzdA==", // "test" in base64, but not a valid nonce
			expectError: true,
			errorMsg:    ErrMsgNonceInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := b.validateSecureNonce(config, tt.nonce)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateSecureNonce_WithValidNonce(t *testing.T) {
	b, _ := getTestBackend(t)

	// Setup a valid config with secure nonce enabled
	config := &ConfigEntry{
		ImapServer:        "localhost",
		ImapPort:          993,
		ImapSsl:           true,
		ConnectionTimeout: 30 * time.Second,
		SecureNonce:       true,
	}

	// Test with a simple valid looking nonce (base64 encoded)
	validNonce := "dGVzdC1ub25jZQ==" // "test-nonce" in base64

	// The validateSecureNonce function expects the nonce to exist in storage
	// For this test, we'll just verify it doesn't crash with a proper base64 nonce
	err := b.validateSecureNonce(config, validNonce)
	// This will likely fail because the nonce isn't in storage, but that's expected
	// We're just testing that the function can decode the base64 properly
	assert.Error(t, err) // Expected to fail because nonce not in storage
	assert.Contains(t, err.Error(), ErrMsgNonceInvalid)
}

func TestBuildAuthResponse(t *testing.T) {
	b, _ := getTestBackend(t)

	loginData := &LoginData{
		Role:     "test-role",
		Username: "testuser",
		Password: "testpass",
		Nonce:    "testnonce",
	}

	role := &imapRole{
		Principals: []string{"testuser"},
	}

	resp, err := b.buildAuthResponse(loginData, role)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Auth)
	assert.Equal(t, "testuser", resp.Auth.DisplayName)
	assert.Equal(t, "testuser", resp.Auth.Alias.Name)
	assert.Equal(t, "test-role", resp.Auth.InternalData["role"])
	assert.Equal(t, "test-role", resp.Auth.Metadata["role"])
	assert.Equal(t, "test-role", resp.Auth.Alias.Metadata["role"])
}

func TestLoadAndValidateRole_Success(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a test role first
	roleData := map[string]interface{}{
		"principals": []string{"testuser@example.com"},
	}

	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data:      roleData,
	}

	_, err := b.HandleRequest(context.Background(), roleReq)
	require.NoError(t, err)

	// Test loading the role
	req := &logical.Request{
		Storage: storage,
	}

	role, err := b.loadAndValidateRole(context.Background(), req, "test-role")

	assert.NoError(t, err)
	assert.NotNil(t, role)
	assert.Equal(t, []string{"testuser@example.com"}, role.Principals)
}

func TestLoadAndValidateRole_NotFound(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Storage: storage,
	}

	role, err := b.loadAndValidateRole(context.Background(), req, "nonexistent-role")

	assert.NoError(t, err)
	assert.Nil(t, role)
}

func TestLoadAndValidateRole_WithCIDRRestriction(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a test role with CIDR restrictions
	roleData := map[string]interface{}{
		"principals":        []string{"testuser@example.com"},
		"token_bound_cidrs": []string{"192.168.1.0/24"},
	}

	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data:      roleData,
	}

	_, err := b.HandleRequest(context.Background(), roleReq)
	require.NoError(t, err)

	tests := []struct {
		name           string
		remoteAddr     string
		hasConnection  bool
		expectError    bool
		expectPermDeny bool
	}{
		{
			name:           "no connection info",
			hasConnection:  false,
			expectError:    true,
			expectPermDeny: true,
		},
		{
			name:           "IP in allowed range",
			remoteAddr:     "192.168.1.100:12345",
			hasConnection:  true,
			expectError:    false,
			expectPermDeny: false,
		},
		{
			name:           "IP outside allowed range",
			remoteAddr:     "10.0.0.1:12345",
			hasConnection:  true,
			expectError:    true,
			expectPermDeny: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &logical.Request{
				Storage: storage,
			}

			if tt.hasConnection {
				req.Connection = &logical.Connection{
					RemoteAddr: tt.remoteAddr,
				}
			}

			role, err := b.loadAndValidateRole(context.Background(), req, "test-role")

			if tt.expectError {
				if tt.expectPermDeny {
					assert.Equal(t, logical.ErrPermissionDenied, err)
				} else {
					assert.Error(t, err)
				}
				assert.Nil(t, role)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, role)
			}
		})
	}
}

func TestExtractLoginData_EdgeCases(t *testing.T) {
	b, _ := getTestBackend(t)

	tests := []struct {
		name         string
		data         map[string]interface{}
		expectError  bool
		errorMsg     string
		expectedData *LoginData
	}{
		{
			name: "all fields present",
			data: map[string]interface{}{
				"role":     "test-role",
				"username": "testuser",
				"password": "testpass",
				"nonce":    "testnonce",
			},
			expectError: false,
			expectedData: &LoginData{
				Role:     "test-role",
				Username: "testuser",
				Password: "testpass",
				Nonce:    "testnonce",
			},
		},
		{
			name: "missing nonce is ok",
			data: map[string]interface{}{
				"role":     "test-role",
				"username": "testuser",
				"password": "testpass",
			},
			expectError: false,
			expectedData: &LoginData{
				Role:     "test-role",
				Username: "testuser",
				Password: "testpass",
				Nonce:    "",
			},
		},
		{
			name: "missing role",
			data: map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
			expectError: true,
			errorMsg:    ErrMsgRoleRequired,
		},
		{
			name: "missing username",
			data: map[string]interface{}{
				"role":     "test-role",
				"password": "testpass",
			},
			expectError: true,
			errorMsg:    ErrMsgUsernameRequired,
		},
		{
			name: "missing password",
			data: map[string]interface{}{
				"role":     "test-role",
				"username": "testuser",
			},
			expectError: true,
			errorMsg:    ErrMsgPasswordRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fieldData := createFieldData(tt.data)

			result, err := b.extractLoginData(fieldData)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedData, result)
			}
		})
	}
}

// Helper function to create field data
func createFieldData(data map[string]interface{}) *framework.FieldData {
	schema := map[string]*framework.FieldSchema{
		"role":     {Type: framework.TypeString},
		"username": {Type: framework.TypeString},
		"password": {Type: framework.TypeString},
		"nonce":    {Type: framework.TypeString},
	}

	return &framework.FieldData{
		Raw:    data,
		Schema: schema,
	}
}
