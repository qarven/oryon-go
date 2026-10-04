package application

import (
	"context"
	"fmt"
)

type EventRegistrationInput struct {
	Name     string
	Identity string
	Channel  string
	Code     string
}

//nolint:forbidigo // ignore for now
func (a *Application) EventRegistration(ctx context.Context, input EventRegistrationInput) error {
	fmt.Printf(`
	registration event:
		name: %s
		identity: %s
		channel: %s
		code: %s
	`, input.Name, input.Identity, input.Channel, input.Code)

	return nil
}
