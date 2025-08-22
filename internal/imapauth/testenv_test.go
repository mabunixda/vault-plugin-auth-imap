package imapauth

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// testEnv encapsulates the test environment
type testEnv struct {
	Backend logical.Backend
	Context context.Context
	Storage logical.Storage
	T       *testing.T
}

// newTestEnv creates a new test environment with a configured backend
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	ctx := context.Background()
	config := &logical.BackendConfig{
		System: &logical.StaticSystemView{},
		Logger: nil,
	}

	b, err := Factory(ctx, config)
	if err != nil {
		t.Fatal(err)
	}

	storage := &logical.InmemStorage{}

	return &testEnv{
		Backend: b,
		Context: ctx,
		Storage: storage,
		T:       t,
	}
}

// configureBackend sets up the basic configuration for testing
func (e *testEnv) configureBackend() {
	e.T.Helper()

	configData := map[string]interface{}{
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
		Storage:   e.Storage,
		Data:      configData,
	}

	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		e.T.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		e.T.Fatal(resp.Error())
	}
}

// createRole creates a test role with the given name
func (e *testEnv) createRole(name string, data map[string]interface{}) {
	e.T.Helper()

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/" + name,
		Storage:   e.Storage,
		Data:      data,
	}

	resp, err := e.Backend.HandleRequest(e.Context, req)
	if err != nil {
		e.T.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		e.T.Fatal(resp.Error())
	}
}
