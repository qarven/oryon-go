package domain

import (
	"errors"
	"time"
)

type VerificationPurpose int16

const (
	VerificationPurposeUnknown           VerificationPurpose = 0
	VerificationPurposeEmailVerification VerificationPurpose = 1
	VerificationPurposePhoneVerification VerificationPurpose = 2
	VerificationPurposePasswordReset     VerificationPurpose = 3
	VerificationPurposeMFAVerification   VerificationPurpose = 4
)

func (p VerificationPurpose) IsValid() bool {
	switch p {
	case VerificationPurposeEmailVerification,
		VerificationPurposePhoneVerification,
		VerificationPurposePasswordReset,
		VerificationPurposeMFAVerification:
		return true
	default:
		return false
	}
}

type VerificationChallenge struct {
	ID          int64
	UserID      *int64
	FlowID      *int64
	Identifier  string
	Purpose     VerificationPurpose
	CodeHash    []byte
	Attempts    int16
	MaxAttempts int16
	IPAddress   *string
	ExpiresAt   time.Time
	ConsumedAt  *time.Time
	CreatedAt   time.Time
}

var (
	ErrVerificationNotFound         = errors.New("verification challenge not found")
	ErrVerificationExpired          = errors.New("verification challenge expired")
	ErrVerificationConsumed         = errors.New("verification challenge already consumed")
	ErrVerificationAttemptsExceeded = errors.New("too many verification attempts")
	ErrIdentifierConflict           = errors.New("identifier already registered")
)

func (v VerificationChallenge) IsExpired(now time.Time) bool {
	return now.After(v.ExpiresAt)
}

func (v VerificationChallenge) IsConsumed() bool {
	return v.ConsumedAt != nil
}

func (v VerificationChallenge) IsAttemptsExceeded() bool {
	return v.Attempts >= v.MaxAttempts
}

func (v *VerificationChallenge) IncrementAttempts() {
	v.Attempts++
}

func (v *VerificationChallenge) Consume(now time.Time) error {
	if err := v.CanAttempt(now); err != nil {
		return err
	}

	v.ConsumedAt = &now

	return nil
}

func (v VerificationChallenge) CanAttempt(now time.Time) error {
	if v.IsConsumed() {
		return ErrVerificationConsumed
	}

	if v.IsExpired(now) {
		return ErrVerificationExpired
	}

	if v.IsAttemptsExceeded() {
		return ErrVerificationAttemptsExceeded
	}

	return nil
}
