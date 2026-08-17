package domain

import (
	"errors"
	"time"
)

type PasswordCredential struct {
	UserID            int64
	Password          string
	PasswordChangedAt time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

var (
	ErrPasswordEmpty              = errors.New("password must not be empty")
	ErrPasswordTooShort           = errors.New("password must be at least 8 characters")
	ErrPasswordCredentialNotFound = errors.New("password credential not found")
)

func NewPasswordCredential(userID int64, hashedPassword string, now time.Time) (*PasswordCredential, error) {
	if hashedPassword == "" {
		return nil, ErrPasswordEmpty
	}

	return &PasswordCredential{
		UserID:            userID,
		Password:          hashedPassword,
		PasswordChangedAt: now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}, nil
}

func (p *PasswordCredential) UpdatePassword(hashedPassword string, now time.Time) error {
	if hashedPassword == "" {
		return ErrPasswordEmpty
	}

	p.Password = hashedPassword
	p.PasswordChangedAt = now
	p.UpdatedAt = now

	return nil
}
