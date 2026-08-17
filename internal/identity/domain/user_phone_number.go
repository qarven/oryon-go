package domain

import (
	"errors"
	"regexp"
	"time"
)

var rePhoneE164 = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

type UserPhoneNumber struct {
	ID         int64
	UserID     int64
	Phone      string
	CreatedAt  time.Time
	VerifiedAt *time.Time
	DeletedAt  *time.Time
}

var (
	ErrPhoneInvalid  = errors.New("phone must be E.164 format")
	ErrPhoneNotFound = errors.New("phone not found")
)

func NewUserPhoneNumber(id, userID int64, phone string, now time.Time) (*UserPhoneNumber, error) {
	if !rePhoneE164.MatchString(phone) {
		return nil, ErrPhoneInvalid
	}

	return &UserPhoneNumber{
		ID:        id,
		UserID:    userID,
		Phone:     phone,
		CreatedAt: now,
	}, nil
}

func (p *UserPhoneNumber) IsVerified() bool {
	return p.VerifiedAt != nil
}

func (p *UserPhoneNumber) MarkVerified(now time.Time) {
	p.VerifiedAt = &now
}
