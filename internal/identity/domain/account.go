package domain

type AccountProvider int16

const (
	AccountProviderUnknown = 0
	AccountProviderGoogle  = 1
)

type Account struct {
	ID                int64
	UserID            int64
	Provider          AccountProvider
	ProviderAccountID string
}
