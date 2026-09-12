package domain

import (
	"errors"
	"time"
)

var (
	ErrSessionNotFound = errors.New("session not found")
)

type Session struct {
	ID            int64
	UserID        int64
	TokenHash     []byte
	CreatedAt     time.Time
	ExpiresAt     time.Time
	LastSeenAt    *time.Time
	RevokedAt     *time.Time
	IPAddress     *string
	UserAgent     *string
	MFAVerifiedAt *time.Time
}

func (s Session) IsExpired(now time.Time) bool {
	return now.After(s.ExpiresAt)
}

func (s Session) IsRevoked() bool {
	return s.RevokedAt != nil
}

func (s Session) IsActive(now time.Time) bool {
	return !s.IsRevoked() && !s.IsExpired(now)
}
