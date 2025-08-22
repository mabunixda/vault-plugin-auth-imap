package imapauth

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
)

func TestInputValidator_ValidateLoginData(t *testing.T) {
	logger := hclog.NewNullLogger()
	validator := NewInputValidator(logger)

	tests := []struct {
		name        string
		username    string
		password    string
		role        string
		nonce       string
		secureNonce bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid login data without secure nonce",
			username:    "testuser",
			password:    "testpass",
			role:        "testrole",
			nonce:       "",
			secureNonce: false,
			expectError: false,
		},
		{
			name:        "valid login data with secure nonce",
			username:    "testuser",
			password:    "testpass",
			role:        "testrole",
			nonce:       "dGVzdG5vbmNl", // base64 encoded "testnonce"
			secureNonce: true,
			expectError: false,
		},
		{
			name:        "missing role",
			username:    "testuser",
			password:    "testpass",
			role:        "",
			nonce:       "",
			secureNonce: false,
			expectError: true,
			errorMsg:    ErrMsgRoleRequired,
		},
		{
			name:        "missing username",
			username:    "",
			password:    "testpass",
			role:        "testrole",
			nonce:       "",
			secureNonce: false,
			expectError: true,
			errorMsg:    ErrMsgUsernameRequired,
		},
		{
			name:        "missing password",
			username:    "testuser",
			password:    "",
			role:        "testrole",
			nonce:       "",
			secureNonce: false,
			expectError: true,
			errorMsg:    ErrMsgPasswordRequired,
		},
		{
			name:        "username too long",
			username:    string(make([]byte, MaxUsernameLength+1)),
			password:    "testpass",
			role:        "testrole",
			nonce:       "",
			secureNonce: false,
			expectError: true,
			errorMsg:    ErrMsgUsernameTooLong,
		},
		{
			name:        "password too long",
			username:    "testuser",
			password:    string(make([]byte, MaxPasswordLength+1)),
			role:        "testrole",
			nonce:       "",
			secureNonce: false,
			expectError: true,
			errorMsg:    ErrMsgPasswordTooLong,
		},
		{
			name:        "secure nonce required but missing",
			username:    "testuser",
			password:    "testpass",
			role:        "testrole",
			nonce:       "",
			secureNonce: true,
			expectError: true,
			errorMsg:    ErrMsgNonceRequired,
		},
		{
			name:        "secure nonce required but invalid base64",
			username:    "testuser",
			password:    "testpass",
			role:        "testrole",
			nonce:       "invalid-base64!!!",
			secureNonce: true,
			expectError: true,
			errorMsg:    ErrMsgNonceDecodeFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateLoginData(tt.username, tt.password, tt.role, tt.nonce, tt.secureNonce)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInputValidator_ValidateRole_EdgeCases(t *testing.T) {
	logger := hclog.NewNullLogger()
	validator := NewInputValidator(logger)

	tests := []struct {
		name        string
		role        string
		expectError bool
	}{
		{
			name:        "valid role",
			role:        "valid-role",
			expectError: false,
		},
		{
			name:        "empty role",
			role:        "",
			expectError: true,
		},
		{
			name:        "whitespace only role",
			role:        "   ",
			expectError: false, // Whitespace is considered valid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateRole(tt.role)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), ErrMsgRoleRequired)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInputValidator_ValidateCredentials_EdgeCases(t *testing.T) {
	logger := hclog.NewNullLogger()
	validator := NewInputValidator(logger)

	tests := []struct {
		name        string
		username    string
		password    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid credentials",
			username:    "user",
			password:    "pass",
			expectError: false,
		},
		{
			name:        "empty username",
			username:    "",
			password:    "pass",
			expectError: true,
			errorMsg:    ErrMsgUsernameRequired,
		},
		{
			name:        "empty password",
			username:    "user",
			password:    "",
			expectError: true,
			errorMsg:    ErrMsgPasswordRequired,
		},
		{
			name:        "both empty",
			username:    "",
			password:    "",
			expectError: true,
			errorMsg:    ErrMsgUsernameRequired,
		},
		{
			name:        "username at max length",
			username:    string(make([]byte, MaxUsernameLength)),
			password:    "pass",
			expectError: false,
		},
		{
			name:        "password at max length",
			username:    "user",
			password:    string(make([]byte, MaxPasswordLength)),
			expectError: false,
		},
		{
			name:        "username over max length",
			username:    string(make([]byte, MaxUsernameLength+1)),
			password:    "pass",
			expectError: true,
			errorMsg:    ErrMsgUsernameTooLong,
		},
		{
			name:        "password over max length",
			username:    "user",
			password:    string(make([]byte, MaxPasswordLength+1)),
			expectError: true,
			errorMsg:    ErrMsgPasswordTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateCredentials(tt.username, tt.password)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInputValidator_ValidateNonce_EdgeCases(t *testing.T) {
	logger := hclog.NewNullLogger()
	validator := NewInputValidator(logger)

	tests := []struct {
		name        string
		nonce       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid base64 nonce",
			nonce:       "dGVzdG5vbmNl", // "testnonce" in base64
			expectError: false,
		},
		{
			name:        "empty nonce",
			nonce:       "",
			expectError: true,
			errorMsg:    ErrMsgNonceRequired,
		},
		{
			name:        "invalid base64",
			nonce:       "not-base64!!!",
			expectError: true,
			errorMsg:    ErrMsgNonceDecodeFailed,
		},
		{
			name:        "base64 with padding",
			nonce:       "dGVzdA==", // "test" in base64 with padding
			expectError: false,
		},
		{
			name:        "base64 without padding",
			nonce:       "dGVzdA", // "test" in base64 without padding
			expectError: true,     // This should actually error due to padding
			errorMsg:    ErrMsgNonceDecodeFailed,
		},
		{
			name:        "whitespace only",
			nonce:       "   ",
			expectError: true,
			errorMsg:    ErrMsgNonceDecodeFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateNonce(tt.nonce)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPrincipalValidator_ValidatePrincipal_RegexTimeout(t *testing.T) {
	logger := hclog.NewNullLogger()
	validator := NewPrincipalValidator(logger)

	// This regex pattern is designed to cause exponential backtracking
	// but our timeout should prevent it from hanging
	maliciousPattern := "(a+)+(b+)+(c+)+"
	principals := []string{maliciousPattern}
	principal := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX" // Long string that won't match

	// This should return false due to timeout, not hang
	result := validator.ValidatePrincipal(principals, principal)
	assert.False(t, result)
}

func TestPrincipalValidator_ValidatePrincipal_LongPattern(t *testing.T) {
	logger := hclog.NewNullLogger()
	validator := NewPrincipalValidator(logger)

	// Create a pattern longer than MaxRegexLength
	longPattern := string(make([]byte, MaxRegexLength+1))
	principals := []string{longPattern}
	principal := "test"

	// Should return false because pattern is too long
	result := validator.ValidatePrincipal(principals, principal)
	assert.False(t, result)
}

func TestPrincipalValidator_ValidatePrincipal_InvalidRegex(t *testing.T) {
	logger := hclog.NewNullLogger()
	validator := NewPrincipalValidator(logger)

	// Invalid regex pattern
	invalidPattern := "[unclosed"
	principals := []string{invalidPattern}
	principal := "test"

	// Should return false due to invalid regex
	result := validator.ValidatePrincipal(principals, principal)
	assert.False(t, result)
}

func TestPrincipalValidator_ValidatePrincipal_RegexMatch(t *testing.T) {
	logger := hclog.NewNullLogger()
	validator := NewPrincipalValidator(logger)

	tests := []struct {
		name      string
		patterns  []string
		principal string
		expected  bool
	}{
		{
			name:      "exact string match",
			patterns:  []string{"test@example.com"},
			principal: "test@example.com",
			expected:  true,
		},
		{
			name:      "regex match",
			patterns:  []string{".*@example\\.com"},
			principal: "user@example.com",
			expected:  true,
		},
		{
			name:      "no match",
			patterns:  []string{".*@example\\.com"},
			principal: "user@other.com",
			expected:  false,
		},
		{
			name:      "multiple patterns, first matches",
			patterns:  []string{"admin@.*", "user@.*"},
			principal: "admin@example.com",
			expected:  true,
		},
		{
			name:      "multiple patterns, second matches",
			patterns:  []string{"admin@.*", "user@.*"},
			principal: "user@example.com",
			expected:  true,
		},
		{
			name:      "empty patterns list",
			patterns:  []string{},
			principal: "anyone@example.com",
			expected:  true,
		},
		{
			name:      "principal too long",
			patterns:  []string{".*"},
			principal: string(make([]byte, MaxUsernameLength+1)),
			expected:  false,
		},
		{
			name:      "empty principal",
			patterns:  []string{".*"},
			principal: "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidatePrincipal(tt.patterns, tt.principal)
			assert.Equal(t, tt.expected, result)
		})
	}
}
