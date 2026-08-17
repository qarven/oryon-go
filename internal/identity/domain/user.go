package domain

type UserStatus int16

const (
	UserStatusUnknown  = 0
	UserStatusActive   = 1
	UserStatusInactive = 2
)

type User struct {
	ID     int64
	Email  string
	Name   string
	Status UserStatus
}
