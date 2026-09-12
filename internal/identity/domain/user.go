package domain

import (
	"errors"
	"time"
)

var (
	ErrUserNotFound = errors.New("user not found")
)

type UserStatus int16

const (
	// Status is unknown/not set
	UserStatusUnknown UserStatus = 0

	// User can normally use the account
	UserStatusActive UserStatus = 1

	// Account exists but is currently inactive
	UserStatusInactive UserStatus = 2

	// Account is temporarily locked, often for security reasons
	UserStatusLocked UserStatus = 3

	// Account has been suspended, usually by an administrator/system
	UserStatusSuspended UserStatus = 4

	// Account has been deleted
	UserStatusDeleted UserStatus = 5
)

func (s UserStatus) IsValid() bool {
	switch s {
	case UserStatusActive,
		UserStatusInactive,
		UserStatusLocked,
		UserStatusSuspended,
		UserStatusDeleted:
		return true
	default:
		return false
	}
}

func (s UserStatus) CanAuthenticate() bool {
	return s == UserStatusActive
}

func (s UserStatus) Value() int16 {
	switch s {
	case UserStatusActive:
		return 1
	case UserStatusInactive:
		return 2
	case UserStatusLocked:
		return 3
	case UserStatusSuspended:
		return 4
	case UserStatusDeleted:
		return 5
	default:
		return 0
	}
}

type User struct {
	ID        int64
	Status    UserStatus
	Name      string
	Username  *string
	AvatarURL *string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

func (u User) IsDeleted() bool {
	return u.DeletedAt != nil || u.Status == UserStatusDeleted
}

func (u User) IsActive() bool {
	return u.Status == UserStatusActive && u.DeletedAt == nil
}

func (u User) CanAuthenticate() bool {
	return u.Status.CanAuthenticate() && u.DeletedAt == nil
}
