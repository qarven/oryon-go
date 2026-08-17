package domain

import (
	"errors"
	"time"
)

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
	case AuthFlowTypeRegistration, AuthFlowTypeLogin, AuthFlowTypeRecovery, AuthFlowTypeStepUpMFA:
		return true
	default:
		return false
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
	case AuthFlowStatePendingIdentifier, AuthFlowStatePendingPassword, AuthFlowStatePendingMFA,
		AuthFlowStatePendingVerification, AuthFlowStateCompleted, AuthFlowStateFailed:
		return true
	default:
		return false
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

var (
	ErrAuthFlowNotFound = errors.New("auth flow not found")
	ErrAuthFlowExpired  = errors.New("auth flow expired")
	ErrAuthFlowInvalid  = errors.New("auth flow is not in valid state")
)

func NewAuthFlow(id int64, userID *int64, flowType AuthFlowType, flowState AuthFlowState, ip, ua *string, ctx map[string]any, now, expiresAt time.Time) (*AuthFlow, error) {
	if !flowType.IsValid() {
		return nil, errors.New("invalid flow type")
	}

	if !flowState.IsValid() {
		return nil, errors.New("invalid flow state")
	}

	if expiresAt.Before(now) {
		return nil, errors.New("expires_at must be in the future")
	}

	if ctx == nil {
		ctx = make(map[string]any)
	}

	return &AuthFlow{
		ID:        id,
		UserID:    userID,
		FlowType:  flowType,
		FlowState: flowState,
		IPAddress: ip,
		UserAgent: ua,
		Context:   ctx,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}, nil
}

func (f *AuthFlow) IsExpired(now time.Time) bool {
	return now.After(f.ExpiresAt)
}

func (f *AuthFlow) Complete(now time.Time) error {
	if f.IsExpired(now) {
		return ErrAuthFlowExpired
	}

	if f.FlowState.IsTerminal() {
		return ErrAuthFlowInvalid
	}

	f.FlowState = AuthFlowStateCompleted
	f.CompletedAt = &now

	return nil
}

func (f *AuthFlow) Fail(now time.Time) {
	f.FlowState = AuthFlowStateFailed
	f.CompletedAt = &now
}
