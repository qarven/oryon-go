package domain

type AccountProvider int16

const (
	AccountProviderUnknown = 0
	AccountProviderGoogle  = 1
)

type Account struct {
	ID                int64
	IdentityID        int64
	Provider          AccountProvider
	ProviderAccountID string
}
