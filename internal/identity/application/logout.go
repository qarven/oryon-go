package application

import (
	"context"
	"errors"
	"log/slog"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type LogoutInput struct {
	RefreshToken string    `validate:"required"`
	Meta         MetaInput `validate:"required"`
}

type LogoutOutput struct{}

type RevokeSessionData struct {
	RefreshToken domain.RefreshToken
	Session      domain.Session
}

func (a *Application) Logout(ctx context.Context, input LogoutInput) (*LogoutOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "Logout")
	defer span.End()

	err := a.validator.Validate(input)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	hashBytes, err := a.sha256.Hash(input.RefreshToken)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash refresh token", "error", err)

		return nil, goerror.NewServer(err)
	}

	storedToken, err := a.repo.GetRefreshTokenByHash(ctx, hashBytes)
	if errors.Is(err, domain.ErrRefreshTokenNotFound) {
		// Idempotent: nothing to revoke.
		return &LogoutOutput{}, nil
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get refresh token by hash", "error", err)

		return nil, goerror.NewServer(err)
	}

	if storedToken.IsRevoked() {
		// Idempotent: nothing to revoke.
		return &LogoutOutput{}, nil
	}

	sess, err := a.repo.GetSessionByID(ctx, storedToken.SessionID)
	if errors.Is(err, domain.ErrSessionNotFound) {
		slog.ErrorContext(ctx, "data integrity violation: refresh token session not found",
			"session_id", storedToken.SessionID,
		)

		return nil, goerror.NewServer(err)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get session by id", "session_id", storedToken.SessionID, "error", err)

		return nil, goerror.NewServer(err)
	}

	now := a.clock.Now()
	storedToken.RevokedAt = &now

	err = a.repo.RevokeSession(ctx, RevokeSessionData{
		RefreshToken: *storedToken,
		Session:      *sess,
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to revoke session",
			"session_id", sess.ID,
			"user_id", sess.UserID,
			"error", err,
		)

		return nil, goerror.NewServer(err)
	}

	a.securityEvent(domain.SecurityEventTypeLogoutSuccess).
		ForUser(&sess.UserID).
		WithMeta(input.Meta).
		With("session_id", sess.ID).
		Emit(ctx)

	return &LogoutOutput{}, nil
}
