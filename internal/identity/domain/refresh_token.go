package domain

import (
	"errors"
	"time"
)

var (
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
)

type RefreshToken struct {
	ID         int64
	SessionID  int64
	TokenHash  []byte
	IssuedAt   time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	ReplacedBy *int64
	CreatedIP  *string
}

func (r RefreshToken) IsExpired(now time.Time) bool {
	return now.After(r.ExpiresAt)
}

func (r RefreshToken) IsRevoked() bool {
	return r.RevokedAt != nil
}

func (r RefreshToken) IsActive(now time.Time) bool {
	return !r.IsRevoked() && !r.IsExpired(now)
}
