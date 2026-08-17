package domain

// Deprecated: Account is kept for backward compatibility, use Identity instead.
type AccountProvider int16

const (
	AccountProviderUnknown AccountProvider = 0
	AccountProviderGoogle  AccountProvider = 1
)

type Account struct {
	ID                int64
	IdentityID        int64
	Provider          AccountProvider
	ProviderAccountID string
}

func (a Account) ToIdentityProvider() IdentityProvider {
	switch a.Provider {
	case AccountProviderGoogle:
		return IdentityProviderGoogle
	default:
		return IdentityProviderUnknown
	}
}
