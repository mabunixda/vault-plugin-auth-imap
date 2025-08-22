package imapauth

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func getTestBackend(t *testing.T) (*backend, logical.Storage) {
	config := &logical.BackendConfig{
		System: &logical.StaticSystemView{},
		Logger: nil,
	}

	b, err := Factory(context.Background(), config)
	assert.NoError(t, err)
	assert.NotNil(t, b)

	return b.(*backend), &logical.InmemStorage{}
}

func TestBackend_Factory(t *testing.T) {
	b, err := Factory(context.Background(), &logical.BackendConfig{})
	assert.NoError(t, err)
	assert.NotNil(t, b)

	// Verify backend type
	backend := b.(*backend)
	assert.NotNil(t, backend.nonces)
}

func TestBackend_FactoryNilConfig(t *testing.T) {
	b, err := Factory(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, b)
}

func TestBackend_Setup(t *testing.T) {
	b, _ := getTestBackend(t)
	assert.NotNil(t, b)

	// Verify backend has required properties
	assert.NotNil(t, b.nonces)
	assert.Equal(t, "auth", b.BackendType.String())

	// Check specific paths exist
	paths := b.Paths
	assert.NotEmpty(t, paths)
	assert.True(t, len(paths) >= 4, "Should have at least 4 paths (login, config, role, nonce)")
}
