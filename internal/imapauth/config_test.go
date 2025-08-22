package imapauth

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestConfig_Write(t *testing.T) {
	b, storage := getTestBackend(t)

	data := map[string]interface{}{
		"imap_server":   "imap.example.com",
		"imap_port":     993,
		"imap_ssl":      true,
		"secure_nonce":  true,
		"token_ttl":     "1h",
		"token_max_ttl": "24h",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Nil(t, resp)

	// Read it back
	req.Operation = logical.ReadOperation
	req.Data = nil

	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, data["imap_server"], resp.Data["imap_server"])
	assert.Equal(t, data["imap_port"], resp.Data["imap_port"])
	assert.Equal(t, data["imap_ssl"], resp.Data["imap_ssl"])
	assert.Equal(t, data["secure_nonce"], resp.Data["secure_nonce"])
}

func TestConfig_ValidateFields(t *testing.T) {
	b, storage := getTestBackend(t)

	testCases := []struct {
		name          string
		data          map[string]interface{}
		expectError   bool
		errorContains string
	}{
		{
			name: "valid config",
			data: map[string]interface{}{
				"imap_server":   "imap.example.com",
				"imap_port":     993,
				"imap_ssl":      true,
				"secure_nonce":  true,
				"token_ttl":     "1h",
				"token_max_ttl": "24h",
			},
			expectError: false,
		},
		{
			name: "missing server",
			data: map[string]interface{}{
				"imap_port": 993,
				"imap_ssl":  true,
			},
			expectError:   true,
			errorContains: "imap_server is required",
		},
		{
			name: "invalid port",
			data: map[string]interface{}{
				"imap_server": "imap.example.com",
				"imap_port":   -1,
				"imap_ssl":    true,
			},
			expectError:   true,
			errorContains: "invalid port number",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config",
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

func TestConfig_ErrorHandling(t *testing.T) {
	b, storage := getTestBackend(t)

	// Test config validation edge cases
	configData := map[string]interface{}{
		"imap_server": "", // Empty server
		"imap_port":   0,  // Invalid port
	}

	writeReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      configData,
	}

	resp, err := b.HandleRequest(context.Background(), writeReq)
	assert.True(t, err != nil || (resp != nil && resp.IsError()))

	// Test config with extreme values
	configData = map[string]interface{}{
		"imap_server": "test.com",
		"imap_port":   65536, // Port too high
	}

	writeReq.Data = configData
	resp, err = b.HandleRequest(context.Background(), writeReq)
	assert.True(t, err != nil || (resp != nil && resp.IsError()))

	// Test config with negative port
	configData = map[string]interface{}{
		"imap_server": "test.com",
		"imap_port":   -1, // Negative port
	}

	writeReq.Data = configData
	resp, err = b.HandleRequest(context.Background(), writeReq)
	assert.True(t, err != nil || (resp != nil && resp.IsError()))
}
