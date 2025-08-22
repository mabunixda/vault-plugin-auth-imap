package imapauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConnectionType_String(t *testing.T) {
	tests := []struct {
		name        string
		connType    ConnectionType
		expectedStr string
	}{
		{
			name:        "Plain connection type",
			connType:    ConnectionPlain,
			expectedStr: "plain",
		},
		{
			name:        "TLS connection type",
			connType:    ConnectionTLS,
			expectedStr: "tls",
		},
		{
			name:        "STARTTLS connection type",
			connType:    ConnectionStartTLS,
			expectedStr: "starttls",
		},
		{
			name:        "Unknown connection type",
			connType:    ConnectionType(999), // Invalid value
			expectedStr: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.connType.String()
			assert.Equal(t, tt.expectedStr, result)
		})
	}
}

func TestConstants_Values(t *testing.T) {
	// Test that important constants have expected values
	assert.Equal(t, ConnectionType(0), ConnectionPlain)
	assert.Equal(t, ConnectionType(1), ConnectionTLS)
	assert.Equal(t, ConnectionType(2), ConnectionStartTLS)

	// Test that timeout and limit constants are reasonable
	assert.Greater(t, DefaultConnectionTimeout.Seconds(), float64(0))
	assert.Greater(t, MaxUsernameLength, 0)
	assert.Greater(t, MaxPasswordLength, 0)
	assert.Greater(t, MaxRegexLength, 0)

	// Test error message constants are not empty
	assert.NotEmpty(t, ErrMsgConfigNotFound)
	assert.NotEmpty(t, ErrMsgRoleRequired)
	assert.NotEmpty(t, ErrMsgUsernameRequired)
	assert.NotEmpty(t, ErrMsgPasswordRequired)
	assert.NotEmpty(t, ErrMsgNonceRequired)
	assert.NotEmpty(t, ErrMsgNonceDecodeFailed)
	assert.NotEmpty(t, ErrMsgNonceInvalid)
	assert.NotEmpty(t, ErrMsgAuthFailed)
}

func TestConstants_Consistency(t *testing.T) {
	// Test that connection type constants are in expected order
	assert.True(t, ConnectionPlain < ConnectionTLS)
	assert.True(t, ConnectionTLS < ConnectionStartTLS)

	// Test that length limits are reasonable
	assert.True(t, MaxUsernameLength >= 50)  // Should allow reasonable usernames
	assert.True(t, MaxPasswordLength >= 100) // Should allow reasonable passwords
	assert.True(t, MaxRegexLength >= 100)    // Should allow reasonable regex patterns

	// Test timeout values are reasonable
	assert.True(t, DefaultConnectionTimeout > 0)
	assert.True(t, DefaultNonceTimeout > 0)
	assert.True(t, RegexExecutionTimeout > 0)
}

func TestCustomErrors(t *testing.T) {
	// Test that custom errors are properly defined
	assert.NotNil(t, ErrConfigurationNil)
	assert.NotNil(t, ErrRoleNotFound)
	assert.NotNil(t, ErrInvalidInput)
	assert.NotNil(t, ErrConnectionFailed)
	assert.NotNil(t, ErrAuthenticationFailed)
	assert.NotNil(t, ErrNonceValidation)

	// Test error messages are not empty
	assert.NotEmpty(t, ErrConfigurationNil.Error())
	assert.NotEmpty(t, ErrRoleNotFound.Error())
	assert.NotEmpty(t, ErrInvalidInput.Error())
	assert.NotEmpty(t, ErrConnectionFailed.Error())
	assert.NotEmpty(t, ErrAuthenticationFailed.Error())
	assert.NotEmpty(t, ErrNonceValidation.Error())
}
