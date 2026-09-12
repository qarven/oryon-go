package application

import "context"

type EventMFAVerificationInput struct {
	Name     string
	Identity string
	Channel  string
	Code     string
}

func (a *Application) EventMFAVerification(ctx context.Context, input EventMFAVerificationInput) error {
	return nil
}
