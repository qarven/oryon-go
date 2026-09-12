package domain

import (
	"errors"
	"time"
)

var (
	ErrPhoneNotFound = errors.New("phone not found")
)

type UserPhoneNumber struct {
	ID         int64
	UserID     int64
	Phone      string
	CreatedAt  time.Time
	VerifiedAt *time.Time
	DeletedAt  *time.Time
}

func (p UserPhoneNumber) IsVerified() bool {
	return p.VerifiedAt != nil
}
