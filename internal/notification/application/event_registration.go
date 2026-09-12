package application

import "context"

type EventRegistrationInput struct {
	Name     string
	Identity string
	Channel  string
	Code     string
}

func (a *Application) EventRegistration(ctx context.Context, input EventRegistrationInput) error {
	return nil
}
