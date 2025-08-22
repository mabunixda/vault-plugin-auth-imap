package imapauth

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestNonce_Create(t *testing.T) {
	b, storage := getTestBackend(t)

	// Configure backend first
	configData := map[string]interface{}{
		"imap_server":  "imap.example.com",
		"imap_port":    993,
		"imap_ssl":     true,
		"secure_nonce": true,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      configData,
	}

	_, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)

	// Test nonce creation
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "nonce",
		Storage:   storage,
		Data:      map[string]interface{}{},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Data["nonce"])

	// Verify nonce is a valid UUID string
	nonce := resp.Data["nonce"].(string)
	assert.NotEmpty(t, nonce)
	// UUID should be 36 characters long (including hyphens)
	assert.Len(t, nonce, 36)
}

func TestNonce_Cleanup(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create multiple nonces
	for i := 0; i < 5; i++ {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "nonce",
			Storage:   storage,
			Data:      map[string]interface{}{},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		assert.NoError(t, err)
		nonce := resp.Data["nonce"].(string)

		// Set some nonces as expired
		if i < 3 {
			b.nonces[nonce] = time.Now().Add(-2 * time.Minute)
		}
	}

	// Verify initial nonce count
	initialCount := len(b.nonces)
	assert.Equal(t, 5, initialCount)

	// Run cleanup
	b.nonceCleanup()

	// Verify expired nonces were cleaned up
	assert.Equal(t, 2, len(b.nonces)) // Only 2 valid nonces should remain
}

func TestNonce_Validation(t *testing.T) {
	b, storage := getTestBackend(t)

	// Configure backend first
	configData := map[string]interface{}{
		"imap_server":  "imap.example.com",
		"imap_port":    993,
		"imap_ssl":     true,
		"secure_nonce": true,
	}

	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      configData,
	}

	_, err := b.HandleRequest(context.Background(), configReq)
	assert.NoError(t, err)

	// Read config to get ConfigEntry
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}

	_, err = b.HandleRequest(context.Background(), readReq)
	assert.NoError(t, err)

	// Get the config from storage directly for testing
	configEntry, err := b.config(context.Background(), storage)
	assert.NoError(t, err)
	assert.NotNil(t, configEntry)

	// Generate a valid nonce
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "nonce",
		Storage:   storage,
		Data:      map[string]interface{}{},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	validNonceStr := resp.Data["nonce"].(string)

	// Test valid nonce - just pass the string as bytes
	isValid := b.nonceValidate(configEntry, []byte(validNonceStr))
	assert.True(t, isValid)

	// Test invalid nonce
	invalidNonce := []byte("invalid-nonce")
	isValid = b.nonceValidate(configEntry, invalidNonce)
	assert.False(t, isValid)

	// Test empty nonce
	isValid = b.nonceValidate(configEntry, []byte{})
	assert.False(t, isValid)
}
