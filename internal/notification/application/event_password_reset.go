package application

import "context"

type EventPasswordResetInput struct {
	Name     string
	Identity string
	Channel  string
	Code     string
}

func (a *Application) EventPasswordReset(ctx context.Context, input EventPasswordResetInput) error {
	return nil
}
