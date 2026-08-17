package domain

type IdentityCredentialType int16

const (
	IdentityCredentialTypeUnknown  = 0
	IdentityCredentialTypePassword = 1
)

func (ict IdentityCredentialType) ToValue() int16 {
	switch ict {
	case IdentityCredentialTypePassword:
		return int16(ict)
	default:
		return IdentityCredentialTypeUnknown
	}
}

type IdentityCredential struct {
	ID           int64
	IdentityID   int64
	Type         IdentityCredentialType
	PasswordHash *string
}
