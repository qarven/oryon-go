package domain

type IdentityStatus int16

const (
	IdentityStatusUnknown  = 0
	IdentityStatusActive   = 1
	IdentityStatusInactive = 2
)

type Identity struct {
	ID     int64
	Email  string
	Name   string
	Status IdentityStatus
}
