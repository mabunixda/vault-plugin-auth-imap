package imapauth

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestRole_CRUD(t *testing.T) {
	b, storage := getTestBackend(t)

	roleData := map[string]interface{}{
		"token_ttl":      "1h",
		"token_max_ttl":  "24h",
		"token_policies": []string{"default"},
		"principals":     []string{"user@example.com"},
	}

	// Create role
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/testrole",
		Storage:   storage,
		Data:      roleData,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Nil(t, resp)

	// Read role
	req.Operation = logical.ReadOperation
	req.Data = nil

	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, roleData["principals"], resp.Data["principals"])

	// List roles
	req.Operation = logical.ListOperation
	req.Path = "role"

	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.Data["keys"], "testrole")

	// Delete role
	req.Operation = logical.DeleteOperation
	req.Path = "role/testrole"

	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Nil(t, resp)

	// Read deleted role
	req.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Nil(t, resp)
}

func TestRole_Validation(t *testing.T) {
	b, storage := getTestBackend(t)

	testCases := []struct {
		name          string
		data          map[string]interface{}
		expectError   bool
		errorContains string
	}{
		{
			name: "valid role",
			data: map[string]interface{}{
				"principals":     []string{"user@example.com"},
				"token_ttl":      "1h",
				"token_max_ttl":  "24h",
				"token_policies": []string{"default"},
			},
			expectError: false,
		},
		{
			name: "missing principals",
			data: map[string]interface{}{
				"token_ttl":      "1h",
				"token_max_ttl":  "24h",
				"token_policies": []string{"default"},
			},
			expectError:   true,
			errorContains: "principals are required",
		},
		{
			name: "invalid token ttl",
			data: map[string]interface{}{
				"principals":     []string{"user@example.com"},
				"token_ttl":      "invalid",
				"token_max_ttl":  "24h",
				"token_policies": []string{"default"},
			},
			expectError:   true,
			errorContains: "token_ttl",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "role/testrole",
				Storage:   storage,
				Data:      tc.data,
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if tc.expectError {
				if resp == nil {
					t.Fatal("expected error response but got nil")
				}
				assert.Contains(t, resp.Error().Error(), tc.errorContains)
			} else {
				assert.NoError(t, err)
				assert.Nil(t, resp)
			}
		})
	}
}

func TestRole_List(t *testing.T) {
	b, storage := getTestBackend(t)

	// List when no roles exist
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	if resp != nil && resp.Data != nil && resp.Data["keys"] != nil {
		assert.Equal(t, 0, len(resp.Data["keys"].([]string)))
	}

	// Create some roles
	roles := []string{"role1", "role2", "role3"}
	for _, roleName := range roles {
		roleData := map[string]interface{}{
			"principals":     []string{fmt.Sprintf("user@%s.com", roleName)},
			"token_ttl":      "1h",
			"token_max_ttl":  "24h",
			"token_policies": []string{"default"},
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      fmt.Sprintf("role/%s", roleName),
			Storage:   storage,
			Data:      roleData,
		}

		_, err := b.HandleRequest(context.Background(), req)
		assert.NoError(t, err)
	}

	// List roles again
	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	if resp.Data != nil && resp.Data["keys"] != nil {
		keys := resp.Data["keys"].([]string)
		assert.Equal(t, 3, len(keys))

		// Check all roles are present
		for _, roleName := range roles {
			assert.Contains(t, keys, roleName)
		}
	}
}

func TestRole_Delete(t *testing.T) {
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

	// Verify role exists by reading it
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/testrole",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), readReq)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Delete the role
	deleteReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/testrole",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), deleteReq)
	assert.NoError(t, err)

	// Verify role no longer exists
	resp, err = b.HandleRequest(context.Background(), readReq)
	assert.NoError(t, err)
	assert.Nil(t, resp) // Should return nil for deleted role

	// Try to delete non-existent role - should not error
	deleteReq = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/nonexistent",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), deleteReq)
	assert.NoError(t, err)
}
