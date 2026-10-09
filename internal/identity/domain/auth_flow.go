package domain

import (
	"errors"
	"time"
)

var (
	ErrAuthFlowNotFound = errors.New("auth flow not found")
)

const TokenType string = "Bearer"

type AuthFlowType int16

const (
	AuthFlowTypeUnknown      AuthFlowType = 0
	AuthFlowTypeRegistration AuthFlowType = 1
	AuthFlowTypeLogin        AuthFlowType = 2
	AuthFlowTypeRecovery     AuthFlowType = 3
	AuthFlowTypeStepUpMFA    AuthFlowType = 4
)

const (
	authFlowTypeRegistrationValue int16 = 1
	authFlowTypeLoginValue        int16 = 2
	authFlowTypeRecoveryValue     int16 = 3
	authFlowTypeStepUpMFAValue    int16 = 4
)

func (t AuthFlowType) IsValid() bool {
	switch t {
	case AuthFlowTypeRegistration,
		AuthFlowTypeLogin,
		AuthFlowTypeRecovery,
		AuthFlowTypeStepUpMFA:
		return true
	default:
		return false
	}
}

func (t AuthFlowType) Value() int16 {
	switch t {
	case AuthFlowTypeRegistration:
		return authFlowTypeRegistrationValue
	case AuthFlowTypeLogin:
		return authFlowTypeLoginValue
	case AuthFlowTypeRecovery:
		return authFlowTypeRecoveryValue
	case AuthFlowTypeStepUpMFA:
		return authFlowTypeStepUpMFAValue
	default:
		return 0
	}
}

type AuthFlowState int16

const (
	AuthFlowStateUnknown             AuthFlowState = 0
	AuthFlowStatePendingIdentifier   AuthFlowState = 1
	AuthFlowStatePendingPassword     AuthFlowState = 2
	AuthFlowStatePendingMFA          AuthFlowState = 3
	AuthFlowStatePendingVerification AuthFlowState = 4
	AuthFlowStateCompleted           AuthFlowState = 5
	AuthFlowStateFailed              AuthFlowState = 6
)

const (
	authFlowStatePendingIdentifierValue   int16 = 1
	authFlowStatePendingPasswordValue     int16 = 2
	authFlowStatePendingMFAValue          int16 = 3
	authFlowStatePendingVerificationValue int16 = 4
	authFlowStateCompletedValue           int16 = 5
)

func (s AuthFlowState) IsValid() bool {
	switch s {
	case AuthFlowStatePendingIdentifier,
		AuthFlowStatePendingPassword,
		AuthFlowStatePendingMFA,
		AuthFlowStatePendingVerification,
		AuthFlowStateCompleted,
		AuthFlowStateFailed:
		return true
	default:
		return false
	}
}

func (s AuthFlowState) Value() int16 {
	switch s {
	case AuthFlowStatePendingIdentifier:
		return authFlowStatePendingIdentifierValue
	case AuthFlowStatePendingPassword:
		return authFlowStatePendingPasswordValue
	case AuthFlowStatePendingMFA:
		return authFlowStatePendingMFAValue
	case AuthFlowStatePendingVerification:
		return authFlowStatePendingVerificationValue
	case AuthFlowStateCompleted:
		return authFlowStateCompletedValue
	case AuthFlowStateFailed:
		return authFlowStateCompletedValue
	default:
		return 0
	}
}

func (s AuthFlowState) IsTerminal() bool {
	return s == AuthFlowStateCompleted || s == AuthFlowStateFailed
}

type AuthFlow struct {
	ID          ID
	UserID      *ID
	FlowType    AuthFlowType
	FlowState   AuthFlowState
	IPAddress   *string
	UserAgent   *string
	Context     map[string]any
	CreatedAt   time.Time
	ExpiresAt   time.Time
	CompletedAt *time.Time
}

func (f AuthFlow) IsExpired(now time.Time) bool {
	return now.After(f.ExpiresAt)
}
