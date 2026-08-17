package application

import (
	"context"
	"errors"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type RefreshTokenInput struct {
	RefreshToken string `validate:"required"`
}

type RefreshTokenOutput struct {
	AccessToken  string
	RefreshToken string
}

func (a *Application) RefreshToken(ctx context.Context, input RefreshTokenInput) (*RefreshTokenOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "RefreshToken")
	defer span.End()

	err := a.validator.Validate(input)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	claims, err := a.refreshJWT.Verify(input.RefreshToken)
	if err != nil {
		return nil, goerror.NewBusiness("invalid refresh token", goerror.CodeUnauthorized)
	}

	revoked, err := a.cache.IsRefreshTokenRevoked(ctx, claims.ID)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	if revoked {
		return nil, goerror.NewBusiness("refresh token has been revoked", goerror.CodeUnauthorized)
	}

	identity, err := a.repo.GetIdentityByEmail(ctx, claims.UserEmail)
	if errors.Is(err, domain.ErrIdentityNotFound) {
		return nil, goerror.NewBusiness("invalid refresh token", goerror.CodeUnauthorized)
	}

	if err != nil {
		return nil, goerror.NewServer(err)
	}

	if identity.Status != domain.IdentityStatusActive {
		return nil, goerror.NewBusiness("account is disabled", goerror.CodeForbidden)
	}

	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl > 0 {
		err = a.cache.RevokeRefreshToken(ctx, claims.ID, ttl)
		if err != nil {
			return nil, goerror.NewServer(err)
		}
	}

	accessToken, refreshToken, err := a.issueTokens(identity.ID, identity.Email)
	if err != nil {
		return nil, err
	}

	return &RefreshTokenOutput{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
