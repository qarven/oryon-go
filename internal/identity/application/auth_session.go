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

// findLogoutTarget resolves the refresh token and its session for logout.
// It returns (nil, nil, nil) when the token is unknown or already revoked,
// so logout stays idempotent without leaking token existence.
func (a *Application) findLogoutTarget(
	ctx context.Context,
	refreshToken string,
) (*domain.RefreshToken, *domain.Session, error) {
	hashBytes, err := a.sha256.Hash(refreshToken)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash refresh token", "error", err)

		return nil, nil, goerror.NewServer(err)
	}

	storedToken, err := a.repo.GetRefreshTokenByHash(ctx, hashBytes)
	if errors.Is(err, domain.ErrRefreshTokenNotFound) {
		return nil, nil, nil
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get refresh token by hash", "error", err)

		return nil, nil, goerror.NewServer(err)
	}

	if storedToken.IsRevoked() {
		return nil, nil, nil
	}

	sess, err := a.repo.GetSessionByID(ctx, storedToken.SessionID)
	if errors.Is(err, domain.ErrSessionNotFound) {
		slog.ErrorContext(
			ctx,
			"data integrity violation: refresh token session not found",
			"session_id",
			storedToken.SessionID,
		)

		return nil, nil, goerror.NewServer(err)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get session by id", "session_id", storedToken.SessionID, "error", err)

		return nil, nil, goerror.NewServer(err)
	}

	return storedToken, sess, nil
}

// Logout terminates the session bound to the given refresh token.
//
// It is idempotent: unknown or already-revoked tokens return success so
// clients can always complete a local logout without leaking token
// existence. The token is located by its SHA-256 hash (no JWT verification),
// so logout also works with an expired JWT. Both the refresh token row and
// its session row are revoked atomically.
func (a *Application) Logout(ctx context.Context, input LogoutInput) (*LogoutOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "Logout")
	defer span.End()

	validateErr := a.validator.Validate(input)
	if validateErr != nil {
		return nil, goerror.NewInvalidInput(validateErr)
	}

	storedToken, sess, err := a.findLogoutTarget(ctx, input.RefreshToken)
	if err != nil {
		return nil, err
	}

	if storedToken == nil || sess == nil {
		// Idempotent: nothing to revoke.
		return &LogoutOutput{}, nil
	}

	now := a.clock.Now()
	storedToken.RevokedAt = &now

	err = a.repo.RevokeSession(ctx, RevokeSessionData{
		RefreshToken: *storedToken,
		Session:      *sess,
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to revoke session", "error", err)

		return nil, goerror.NewServer(err)
	}

	a.logSecurityEvent(
		ctx,
		&sess.UserID,
		domain.SecurityEventTypeLogoutSuccess,
		input.Meta,
		map[string]any{"session_id": sess.ID},
	)

	return &LogoutOutput{}, nil
}
