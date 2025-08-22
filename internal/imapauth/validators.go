package imapauth

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/hashicorp/go-hclog"
)

// InputValidator handles validation of user inputs
type InputValidator struct {
	logger hclog.Logger
}

// NewInputValidator creates a new input validator
func NewInputValidator(logger hclog.Logger) *InputValidator {
	return &InputValidator{
		logger: logger,
	}
}

// ValidateLoginData validates all login input data
func (iv *InputValidator) ValidateLoginData(username, password, role, nonce string, secureNonce bool) error {
	if err := iv.ValidateRole(role); err != nil {
		return err
	}

	if err := iv.ValidateCredentials(username, password); err != nil {
		return err
	}

	if secureNonce {
		if err := iv.ValidateNonce(nonce); err != nil {
			return err
		}
	}

	return nil
}

// ValidateRole validates the role field
func (iv *InputValidator) ValidateRole(role string) error {
	if role == "" {
		return fmt.Errorf("%w: %s", ErrInvalidInput, ErrMsgRoleRequired)
	}
	return nil
}

// ValidateCredentials validates username and password
func (iv *InputValidator) ValidateCredentials(username, password string) error {
	if username == "" {
		return fmt.Errorf("%w: %s", ErrInvalidInput, ErrMsgUsernameRequired)
	}
	if password == "" {
		return fmt.Errorf("%w: %s", ErrInvalidInput, ErrMsgPasswordRequired)
	}

	if len(username) > MaxUsernameLength {
		return fmt.Errorf("%w: %s", ErrInvalidInput, ErrMsgUsernameTooLong)
	}
	if len(password) > MaxPasswordLength {
		return fmt.Errorf("%w: %s", ErrInvalidInput, ErrMsgPasswordTooLong)
	}

	return nil
}

// ValidateNonce validates and decodes a nonce
func (iv *InputValidator) ValidateNonce(nonce string) error {
	if nonce == "" {
		return fmt.Errorf("%w: %s", ErrNonceValidation, ErrMsgNonceRequired)
	}

	_, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNonceValidation, ErrMsgNonceDecodeFailed)
	}

	return nil
}

// PrincipalValidator handles validation of user principals against role patterns
type PrincipalValidator struct {
	logger hclog.Logger
}

// NewPrincipalValidator creates a new principal validator
func NewPrincipalValidator(logger hclog.Logger) *PrincipalValidator {
	return &PrincipalValidator{
		logger: logger,
	}
}

// ValidatePrincipal checks if a principal matches any of the allowed patterns
func (pv *PrincipalValidator) ValidatePrincipal(principals []string, principal string) bool {
	// No principals configured means all are allowed
	if len(principals) == 0 {
		return true
	}

	// Sanitize principal
	if len(principal) == 0 || len(principal) > MaxUsernameLength {
		return false
	}

	// Direct string match first (fastest)
	if slices.Contains(principals, principal) {
		return true
	}

	// Check regex patterns
	pv.logger.Debug("principal not in list - checking regex patterns", "principal", principal)
	return pv.validateWithRegex(principals, principal)
}

// validateWithRegex checks if principal matches any regex patterns
func (pv *PrincipalValidator) validateWithRegex(principals []string, principal string) bool {
	for _, pattern := range principals {
		// Limit regex pattern length to prevent ReDoS
		if len(pattern) > MaxRegexLength {
			pv.logger.Warn(LogMsgRegexTooLong, "pattern_length", len(pattern))
			continue
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			pv.logger.Warn(LogMsgRegexInvalid, "pattern", pattern, "error", err)
			continue
		}

		// Use timeout to prevent ReDoS attacks
		if pv.matchWithTimeout(re, principal, pattern) {
			return true
		}
	}
	return false
}

// matchWithTimeout executes regex match with a timeout to prevent ReDoS
func (pv *PrincipalValidator) matchWithTimeout(re *regexp.Regexp, principal, pattern string) bool {
	matched := make(chan bool, 1)
	go func() {
		matched <- re.MatchString(principal)
	}()

	select {
	case result := <-matched:
		if result {
			pv.logger.Debug("principal matched regex pattern", "principal", principal, "pattern", pattern)
		}
		return result
	case <-time.After(RegexExecutionTimeout):
		pv.logger.Warn(LogMsgRegexTimeout, "pattern", pattern, "principal", principal)
		return false
	}
}
