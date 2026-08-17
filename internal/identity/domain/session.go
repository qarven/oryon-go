package domain

import (
	"errors"
	"time"
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

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionRevoked  = errors.New("session revoked")
)

func NewSession(id, userID int64, tokenHash []byte, now, expiresAt time.Time, ip, ua *string) (*Session, error) {
	if len(tokenHash) == 0 {
		return nil, errors.New("token hash must not be empty")
	}

	if expiresAt.Before(now) {
		return nil, errors.New("expires_at must be in the future")
	}

	return &Session{
		ID:        id,
		UserID:    userID,
		TokenHash: tokenHash,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		IPAddress: ip,
		UserAgent: ua,
	}, nil
}

func (s *Session) IsExpired(now time.Time) bool {
	return now.After(s.ExpiresAt)
}

func (s *Session) IsRevoked() bool {
	return s.RevokedAt != nil
}

func (s *Session) IsActive(now time.Time) bool {
	return !s.IsRevoked() && !s.IsExpired(now)
}

func (s *Session) Revoke(now time.Time) error {
	if s.IsRevoked() {
		return ErrSessionRevoked
	}

	s.RevokedAt = &now

	return nil
}

func (s *Session) Touch(now time.Time) {
	s.LastSeenAt = &now
}

func (s *Session) MarkMFAVerified(now time.Time) {
	s.MFAVerifiedAt = &now
}
