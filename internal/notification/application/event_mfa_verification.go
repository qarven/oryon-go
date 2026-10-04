package application

import (
	"context"
	"fmt"
)

type EventMFAVerificationInput struct {
	Name     string
	Identity string
	Channel  string
	Code     string
}

//nolint:forbidigo // ignore for now
func (a *Application) EventMFAVerification(ctx context.Context, input EventMFAVerificationInput) error {
	fmt.Printf(`
	mfa verivication event:
		name: %s
		identity: %s
		channel: %s
		code: %s
	`, input.Name, input.Identity, input.Channel, input.Code)

	return nil
}
