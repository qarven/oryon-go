package domain

import (
	"errors"
	"time"
)

type UserStatus int16

const (
	UserStatusUnknown   UserStatus = 0
	UserStatusActive    UserStatus = 1
	UserStatusInactive  UserStatus = 2
	UserStatusLocked    UserStatus = 3
	UserStatusSuspended UserStatus = 4
	UserStatusDeleted   UserStatus = 5
)

func (s UserStatus) IsValid() bool {
	switch s {
	case UserStatusActive, UserStatusInactive, UserStatusLocked, UserStatusSuspended, UserStatusDeleted:
		return true
	default:
		return false
	}
}

func (s UserStatus) CanAuthenticate() bool {
	return s == UserStatusActive
}

type User struct {
	ID        int64
	Status    UserStatus
	Name      string
	AvatarURL *string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

var (
	ErrUserInvalidName   = errors.New("user name must not be empty")
	ErrUserInvalidStatus = errors.New("invalid user status")
)

func NewUser(id int64, name string, avatarURL *string, now time.Time) (*User, error) {
	if name == "" {
		return nil, ErrUserInvalidName
	}

	return &User{
		ID:        id,
		Status:    UserStatusActive,
		Name:      name,
		AvatarURL: avatarURL,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (u *User) IsDeleted() bool {
	return u.DeletedAt != nil || u.Status == UserStatusDeleted
}

func (u *User) IsActive() bool {
	return u.Status == UserStatusActive && u.DeletedAt == nil
}

func (u *User) CanAuthenticate() bool {
	return u.Status.CanAuthenticate() && u.DeletedAt == nil
}

func (u *User) UpdateProfile(name *string, avatarURL *string, now time.Time) error {
	if name != nil {
		if *name == "" {
			return ErrUserInvalidName
		}

		u.Name = *name
	}

	if avatarURL != nil {
		if *avatarURL == "" {
			u.AvatarURL = nil
		} else {
			u.AvatarURL = avatarURL
		}
	}

	u.UpdatedAt = now

	return nil
}

func (u *User) SoftDelete(now time.Time) {
	u.Status = UserStatusDeleted
	u.DeletedAt = &now
	u.UpdatedAt = now
}
