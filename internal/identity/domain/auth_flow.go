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
		return 1
	case AuthFlowTypeLogin:
		return 2
	case AuthFlowTypeRecovery:
		return 3
	case AuthFlowTypeStepUpMFA:
		return 4
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
		return 1
	case AuthFlowStatePendingPassword:
		return 2
	case AuthFlowStatePendingMFA:
		return 3
	case AuthFlowStatePendingVerification:
		return 4
	case AuthFlowStateCompleted:
		return 5
	case AuthFlowStateFailed:
		return 5
	default:
		return 0
	}
}

func (s AuthFlowState) IsTerminal() bool {
	return s == AuthFlowStateCompleted || s == AuthFlowStateFailed
}

type AuthFlow struct {
	ID          int64
	UserID      *int64
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
