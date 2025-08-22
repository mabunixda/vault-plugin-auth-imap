package imapauth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestBackend_PeriodicFunc(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Storage: storage,
	}

	err := b.periodicFunc(context.Background(), req)
	assert.NoError(t, err)
}

func TestBackend_AuthRenew(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a role first
	roleData := map[string]interface{}{
		"principals":     []string{"test@example.com"},
		"token_ttl":      "1h",
		"token_max_ttl":  "24h",
		"token_policies": []string{"default"},
	}

	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/testrole",
		Storage:   storage,
		Data:      roleData,
	}

	_, err := b.HandleRequest(context.Background(), roleReq)
	assert.NoError(t, err)

	req := &logical.Request{
		Storage: storage,
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"role": "testrole",
			},
			Metadata: map[string]string{
				"role": "testrole",
			},
			DisplayName: "test@example.com",
		},
	}

	resp, err := b.pathAuthRenew(context.Background(), req, nil)
	assert.NoError(t, err)
	assert.NotNil(t, resp) // Should return renewed auth
	assert.NotNil(t, resp.Auth)
}

func TestRole_ExistenceCheck(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a role first
	roleData := map[string]interface{}{
		"principals":     []string{"test@example.com"},
		"token_ttl":      "1h",
		"token_max_ttl":  "24h",
		"token_policies": []string{"default"},
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/testrole",
		Storage:   storage,
		Data:      roleData,
	}

	_, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)

	// Test existence check for existing role
	data := &framework.FieldData{
		Raw:    map[string]interface{}{"name": "testrole"},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	}

	exists, err := b.pathRoleExistenceCheck(context.Background(), req, data)
	assert.NoError(t, err)
	assert.True(t, exists)

	// Test existence check for non-existing role
	data = &framework.FieldData{
		Raw:    map[string]interface{}{"name": "nonexistent"},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	}

	exists, err = b.pathRoleExistenceCheck(context.Background(), req, data)
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestConfig_ReadNonExistent(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Nil(t, resp) // Should return nil when no config exists
}

func TestBackend_PeriodicFunc_Execution(t *testing.T) {
	b, _ := getTestBackend(t)

	// Test periodic function execution
	ctx := context.Background()
	req := &logical.Request{
		Storage: nil, // Periodic function doesn't use storage directly
	}

	// Should not error even with minimal setup
	err := b.periodicFunc(ctx, req)
	assert.NoError(t, err)
}

func TestBackend_AuthRenew_MissingData(t *testing.T) {
	b, storage := getTestBackend(t)

	// Test auth renewal with missing internal data
	req := &logical.Request{
		Storage: storage,
		Auth: &logical.Auth{
			Period: 300, // 5 minutes
		},
		// Missing InternalData
	}

	resp, err := b.pathAuthRenew(context.Background(), req, nil)
	// Should handle gracefully - might return error or empty response
	assert.True(t, err != nil || resp == nil || (resp != nil && resp.IsError()))
}

func TestBackend_AuthRenew_InvalidRole(t *testing.T) {
	b, storage := getTestBackend(t)

	// Test auth renewal with invalid role in internal data
	req := &logical.Request{
		Storage: storage,
		Auth: &logical.Auth{
			Period: 300,
			InternalData: map[string]interface{}{
				"role": "nonexistent-role",
			},
		},
	}

	resp, err := b.pathAuthRenew(context.Background(), req, nil)
	// Should return error for invalid role
	assert.True(t, err != nil || (resp != nil && resp.IsError()))
}

func TestBackend_PathHelp(t *testing.T) {
	b, _ := getTestBackend(t)

	// Test help for login path
	loginPath := b.pathLogin()
	assert.NotNil(t, loginPath)

	// Test help for config path
	configPath := b.pathConfig()
	assert.NotNil(t, configPath)

	// Test help for role path
	rolePath := b.pathRole()
	assert.NotNil(t, rolePath)

	// Test help for nonce path
	noncePath := b.pathNonce()
	assert.NotNil(t, noncePath)
}

func TestBackend_CleanupOperations(t *testing.T) {
	b, _ := getTestBackend(t)

	// Add some test nonces
	for i := 0; i < 5; i++ {
		nonce := fmt.Sprintf("test-nonce-%d", i)
		if i < 3 {
			// Mark some as expired
			b.nonces[nonce] = time.Now().Add(-2 * time.Minute)
		} else {
			// Mark some as valid
			b.nonces[nonce] = time.Now().Add(2 * time.Minute)
		}
	}

	// Verify initial count
	assert.Equal(t, 5, len(b.nonces))

	// Run cleanup
	b.nonceCleanup()

	// Verify expired nonces were removed
	assert.Equal(t, 2, len(b.nonces))
}
