package domain

import (
	"errors"
	"time"
)

var (
	ErrPhoneNotFound = errors.New("phone not found")
)

type UserPhoneNumber struct {
	ID         ID
	UserID     ID
	Phone      string
	CreatedAt  time.Time
	VerifiedAt *time.Time
	DeletedAt  *time.Time
}

func (p UserPhoneNumber) IsVerified() bool {
	return p.VerifiedAt != nil
}
