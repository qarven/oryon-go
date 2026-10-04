package application

import (
	"context"
	"fmt"
)

type EventPasswordResetInput struct {
	Name     string
	Identity string
	Channel  string
	Code     string
}

//nolint:forbidigo // ignore for now
func (a *Application) EventPasswordReset(ctx context.Context, input EventPasswordResetInput) error {
	fmt.Printf(`
	password reset event:
		name: %s
		identity: %s
		channel: %s
		code: %s
	`, input.Name, input.Identity, input.Channel, input.Code)

	return nil
}
