package domain

type CredentialType int16

const (
	CredentialTypeUnknown  = 0
	CredentialTypePassword = 1
)

func (ct CredentialType) ToValue() int16 {
	switch ct {
	case CredentialTypePassword:
		return int16(ct)
	default:
		return CredentialTypeUnknown
	}
}

type Credential struct {
	ID           int64
	UserID       int64
	Type         CredentialType
	PasswordHash *string
}
