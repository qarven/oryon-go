package application

import (
	"context"
	"errors"
	"time"

	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

type LogoutInput struct {
	RefreshToken string `validate:"required"`
}

func (a *Application) Logout(ctx context.Context, input LogoutInput) error {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "Logout")
	defer span.End()

	err := a.validator.Validate(input)
	if err != nil {
		return goerror.NewInvalidInput(err)
	}

	claims, err := a.refreshJWT.Verify(input.RefreshToken)
	if errors.Is(err, jwt.ErrTokenExpired) {
		return nil
	}

	if err != nil {
		return goerror.NewBusiness("invalid refresh token", goerror.CodeInvalidInput)
	}

	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl <= 0 {
		return nil
	}

	err = a.cache.RevokeRefreshToken(ctx, claims.ID, ttl)
	if err != nil {
		return goerror.NewServer(err)
	}

	return nil
}
