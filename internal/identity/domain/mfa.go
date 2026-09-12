package domain

import (
	"errors"
	"time"
)

var (
	ErrMfaFactorNotFound  = errors.New("mfa factor not found")
	ErrTotpFactorNotFound = errors.New("totp factor not found")
	ErrBackupCodeNotFound = errors.New("backup code not found")
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
	case MfaFactorTypeTOTP,
		MfaFactorTypeSMS,
		MfaFactorTypeEmail,
		MfaFactorTypeWebAuthn,
		MfaFactorTypeBackupCode:
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

func (f MfaFactor) IsVerified() bool {
	return f.VerifiedAt != nil
}

func (f MfaFactor) IsRevoked() bool {
	return f.RevokedAt != nil
}

func (f MfaFactor) IsActive() bool {
	return !f.IsRevoked()
}

type TotpAlgorithm int16

const (
	TotpAlgorithmUnknown TotpAlgorithm = 0
	TotpAlgorithmSHA1    TotpAlgorithm = 1
	TotpAlgorithmSHA256  TotpAlgorithm = 2
	TotpAlgorithmSHA512  TotpAlgorithm = 3
)

func TotpAlgorithmFrom(value int16) TotpAlgorithm {
	switch value {
	case 1:
		return TotpAlgorithmSHA1
	case 2:
		return TotpAlgorithmSHA256
	case 3:
		return TotpAlgorithmSHA512
	default:
		return TotpAlgorithmUnknown
	}
}

func (a TotpAlgorithm) IsValid() bool {
	switch a {
	case TotpAlgorithmSHA1,
		TotpAlgorithmSHA256,
		TotpAlgorithmSHA512:
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

type BackupCode struct {
	ID        int64
	UserID    int64
	CodeHash  []byte
	UsedAt    *time.Time
	CreatedAt time.Time
}

func (b BackupCode) IsUsed() bool {
	return b.UsedAt != nil
}
