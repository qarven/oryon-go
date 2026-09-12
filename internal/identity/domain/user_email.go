package domain

import (
	"errors"
	"time"
)

var (
	ErrEmailNotFound        = errors.New("email not found")
	ErrPrimaryEmailNotFound = errors.New("primary email not found")
)

type UserEmail struct {
	ID         int64
	UserID     int64
	Email      string
	IsPrimary  bool
	CreatedAt  time.Time
	VerifiedAt *time.Time
	DeletedAt  *time.Time
}

func (e UserEmail) IsVerified() bool {
	return e.VerifiedAt != nil
}

func (e UserEmail) IsDeleted() bool {
	return e.DeletedAt != nil
}
