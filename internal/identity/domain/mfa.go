package domain

import (
	"errors"
	"time"
)

type MfaFactorType int16

const (
	MfaFactorTypeUnknown    MfaFactorType = 0
	MfaFactorTypeTOTP       MfaFactorType = 1
	MfaFactorTypeSMS        MfaFactorType = 2
	MfaFactorTypeEmail      MfaFactorType = 3
	MfaFactorTypeWebAuthn   MfaFactorType = 4
	MfaFactorTypeBackupCode MfaFactorType = 5
)

func (t MfaFactorType) IsValid() bool {
	switch t {
	case MfaFactorTypeTOTP, MfaFactorTypeSMS, MfaFactorTypeEmail, MfaFactorTypeWebAuthn, MfaFactorTypeBackupCode:
		return true
	default:
		return false
	}
}

type MfaFactor struct {
	ID         int64
	UserID     int64
	Type       MfaFactorType
	Name       string
	CreatedAt  time.Time
	VerifiedAt *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

var (
	ErrMfaFactorNotFound      = errors.New("mfa factor not found")
	ErrMfaFactorAlreadyExists = errors.New("mfa factor already exists")
	ErrMfaFactorNotVerified   = errors.New("mfa factor not verified")
	ErrMfaFactorRevoked       = errors.New("mfa factor revoked")
)

func NewMfaFactor(id, userID int64, factorType MfaFactorType, name string, now time.Time) (*MfaFactor, error) {
	if !factorType.IsValid() {
		return nil, errors.New("invalid mfa factor type")
	}

	if name == "" {
		return nil, errors.New("mfa factor name must not be empty")
	}

	return &MfaFactor{
		ID:        id,
		UserID:    userID,
		Type:      factorType,
		Name:      name,
		CreatedAt: now,
	}, nil
}

func (f *MfaFactor) IsVerified() bool {
	return f.VerifiedAt != nil
}

func (f *MfaFactor) IsRevoked() bool {
	return f.RevokedAt != nil
}

func (f *MfaFactor) IsActive() bool {
	return !f.IsRevoked()
}

func (f *MfaFactor) Verify(now time.Time) {
	f.VerifiedAt = &now
}

func (f *MfaFactor) Revoke(now time.Time) error {
	if f.IsRevoked() {
		return ErrMfaFactorRevoked
	}

	f.RevokedAt = &now

	return nil
}

func (f *MfaFactor) Touch(now time.Time) {
	f.LastUsedAt = &now
}

type TotpAlgorithm int16

const (
	TotpAlgorithmUnknown TotpAlgorithm = 0
	TotpAlgorithmSHA1    TotpAlgorithm = 1
	TotpAlgorithmSHA256  TotpAlgorithm = 2
	TotpAlgorithmSHA512  TotpAlgorithm = 3
)

func (a TotpAlgorithm) IsValid() bool {
	switch a {
	case TotpAlgorithmSHA1, TotpAlgorithmSHA256, TotpAlgorithmSHA512:
		return true
	default:
		return false
	}
}

type TotpFactor struct {
	FactorID  int64
	Secret    []byte
	Algorithm TotpAlgorithm
	Digits    int16
	Period    int16
	CreatedAt time.Time
}

var (
	ErrTotpFactorNotFound = errors.New("totp factor not found")
	ErrTotpInvalidCode    = errors.New("invalid totp code")
)

func NewTotpFactor(factorID int64, secret []byte, algo TotpAlgorithm, digits, period int16, now time.Time) (*TotpFactor, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret must not be empty")
	}

	if !algo.IsValid() {
		return nil, errors.New("invalid totp algorithm")
	}

	if digits != 6 && digits != 8 {
		return nil, errors.New("digits must be 6 or 8")
	}

	if period <= 0 {
		return nil, errors.New("period must be positive")
	}

	return &TotpFactor{
		FactorID:  factorID,
		Secret:    secret,
		Algorithm: algo,
		Digits:    digits,
		Period:    period,
		CreatedAt: now,
	}, nil
}

type BackupCode struct {
	ID        int64
	UserID    int64
	CodeHash  []byte
	UsedAt    *time.Time
	CreatedAt time.Time
}

var (
	ErrBackupCodeNotFound = errors.New("backup code not found")
	ErrBackupCodeUsed     = errors.New("backup code already used")
	ErrBackupCodeInvalid  = errors.New("invalid backup code")
	ErrNoBackupCodesLeft  = errors.New("no backup codes remaining")
)

func NewBackupCode(id, userID int64, codeHash []byte, now time.Time) (*BackupCode, error) {
	if len(codeHash) == 0 {
		return nil, errors.New("code hash must not be empty")
	}

	return &BackupCode{
		ID:        id,
		UserID:    userID,
		CodeHash:  codeHash,
		CreatedAt: now,
	}, nil
}

func (b *BackupCode) IsUsed() bool {
	return b.UsedAt != nil
}

func (b *BackupCode) MarkUsed(now time.Time) error {
	if b.IsUsed() {
		return ErrBackupCodeUsed
	}

	b.UsedAt = &now

	return nil
}
