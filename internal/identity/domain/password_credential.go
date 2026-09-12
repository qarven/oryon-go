package domain

import (
	"errors"
	"time"
)

var (
	ErrPasswordCredentialNotFound = errors.New("password credential not found")
)

type PasswordCredential struct {
	UserID            int64
	Password          string
	PasswordChangedAt time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}
