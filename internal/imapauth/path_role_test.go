package imapauth

import (
	"context"
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
