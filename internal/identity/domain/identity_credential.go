package domain

// Deprecated: IdentityCredential is kept for backward compatibility, use PasswordCredential instead.
type IdentityCredentialType int16

const (
	IdentityCredentialTypeUnknown  IdentityCredentialType = 0
	IdentityCredentialTypePassword IdentityCredentialType = 1
)

func (ict IdentityCredentialType) ToValue() int16 {
	switch ict {
	case IdentityCredentialTypePassword:
		return int16(ict)
	default:
		return int16(IdentityCredentialTypeUnknown)
	}
}

type IdentityCredential struct {
	ID           int64
	IdentityID   int64
	Type         IdentityCredentialType
	PasswordHash *string
}

func (c IdentityCredential) ToPasswordCredential() *PasswordCredential {
	if c.PasswordHash == nil {
		return nil
	}

	return &PasswordCredential{
		UserID:   c.IdentityID,
		Password: *c.PasswordHash,
	}
}
