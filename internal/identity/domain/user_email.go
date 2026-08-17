package domain

import (
	"errors"
	"strings"
	"time"
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

var (
	ErrEmailEmpty            = errors.New("email must not be empty")
	ErrEmailAlreadyExists    = errors.New("email already exists")
	ErrEmailNotFound         = errors.New("email not found")
	ErrPrimaryEmailNotFound  = errors.New("primary email not found")
	ErrCannotRemovePrimary   = errors.New("cannot remove primary email without replacement")
	ErrCannotRemoveLastEmail = errors.New("cannot remove last email")
)

func NewUserEmail(id, userID int64, email string, isPrimary bool, now time.Time) (*UserEmail, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, ErrEmailEmpty
	}

	return &UserEmail{
		ID:        id,
		UserID:    userID,
		Email:     email,
		IsPrimary: isPrimary,
		CreatedAt: now,
	}, nil
}

func (e *UserEmail) IsVerified() bool {
	return e.VerifiedAt != nil
}

func (e *UserEmail) IsDeleted() bool {
	return e.DeletedAt != nil
}

func (e *UserEmail) MarkVerified(now time.Time) {
	e.VerifiedAt = &now
}

func (e *UserEmail) SoftDelete(now time.Time) {
	e.DeletedAt = &now
}
