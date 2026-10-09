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
	ID         ID
	UserID     ID
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

const (
	totpAlgorithmSHA1Value   int16 = 1
	totpAlgorithmSHA256Value int16 = 2
	totpAlgorithmSHA512Value int16 = 3
)

func TotpAlgorithmFrom(value int16) TotpAlgorithm {
	switch value {
	case totpAlgorithmSHA1Value:
		return TotpAlgorithmSHA1
	case totpAlgorithmSHA256Value:
		return TotpAlgorithmSHA256
	case totpAlgorithmSHA512Value:
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
	FactorID  ID
	Secret    []byte
	Algorithm TotpAlgorithm
	Digits    int16
	Period    int16
	CreatedAt time.Time
}

type BackupCode struct {
	ID        ID
	UserID    ID
	CodeHash  []byte
	UsedAt    *time.Time
	CreatedAt time.Time
}

func (b BackupCode) IsUsed() bool {
	return b.UsedAt != nil
}
