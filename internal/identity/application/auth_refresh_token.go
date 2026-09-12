package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type RefreshTokenInput struct {
	RefreshToken string    `validate:"required"`
	Meta         MetaInput `validate:"required"`
}

type RefreshTokenOutput struct {
	Token        string
	RefreshToken string
	ExpiresIn    int64
}

type RotateRefreshTokenData struct {
	OldRefreshToken domain.RefreshToken
	NewRefreshToken domain.RefreshToken
	Session         domain.Session
}

func (a *Application) RefreshToken(ctx context.Context, input RefreshTokenInput) (*RefreshTokenOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "RefreshToken")
	defer span.End()

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	claims, err := a.refreshJWT.Verify(input.RefreshToken)
	if err != nil {
		slog.WarnContext(ctx, "invalid or expired refresh token", "error", err)

		return nil, goerror.NewBusiness("invalid or expired refresh token", goerror.CodeUnauthorized)
	}

	hashBytes, err := a.sha256.Hash(input.RefreshToken)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash refresh token", "error", err)

		return nil, goerror.NewServer(err)
	}

	rt, err := a.repo.GetRefreshTokenByHash(ctx, hashBytes)
	if errors.Is(err, domain.ErrRefreshTokenNotFound) {
		slog.WarnContext(ctx, "refresh token not found")

		return nil, goerror.NewBusiness("refresh token not found", goerror.CodeUnauthorized)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get refresh token by hash", "error", err)

		return nil, goerror.NewServer(err)
	}

	now := a.clock.Now()

	if rt.IsRevoked() {
		slog.WarnContext(ctx, "refresh token already revoked")

		return nil, goerror.NewBusiness("refresh token revoked", goerror.CodeUnauthorized)
	}

	if rt.IsExpired(now) {
		slog.WarnContext(ctx, "refresh token already expired")

		return nil, goerror.NewBusiness("refresh token expired", goerror.CodeUnauthorized)
	}

	sess, err := a.repo.GetSessionByID(ctx, rt.SessionID)
	if errors.Is(err, domain.ErrSessionNotFound) {
		slog.ErrorContext(ctx, "data integrity violation: refresh token session not found", "session_id", rt.SessionID)

		return nil, goerror.NewServer(err)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get session by id", "session_id", rt.SessionID, "error", err)

		return nil, goerror.NewServer(err)
	}

	if sess.IsRevoked() {
		slog.WarnContext(ctx, "session already revoked")

		return nil, goerror.NewBusiness("session revoked", goerror.CodeUnauthorized)
	}

	if sess.IsExpired(now) {
		slog.WarnContext(ctx, "session already expired")

		return nil, goerror.NewBusiness("session expired", goerror.CodeUnauthorized)
	}

	if sess.UserID != claims.UserID {
		slog.ErrorContext(ctx, "data integrity violation: session user does not match refresh token user",
			"session_id", sess.ID,
			"session_user_id", sess.UserID,
			"token_user_id", claims.UserID,
		)
		err := fmt.Errorf("session user %d does not match token user %d", sess.UserID, claims.UserID)

		return nil, goerror.NewServer(err)
	}

	access, newRefresh, err := a.issueTokens(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}

	newID := a.uid.Generate()

	newHash, err := a.sha256.Hash(newRefresh)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash new refresh token", "error", err)

		return nil, goerror.NewServer(err)
	}

	if err := a.repo.RotateRefreshToken(ctx, RotateRefreshTokenData{
		OldRefreshToken: domain.RefreshToken{
			ID:         rt.ID,
			SessionID:  rt.SessionID,
			RevokedAt:  &now,
			ReplacedBy: &newID,
		},
		NewRefreshToken: domain.RefreshToken{
			ID:        newID,
			SessionID: sess.ID,
			TokenHash: newHash,
			IssuedAt:  now,
			ExpiresAt: now.Add(a.config.GetDay("modules.identity.jwt.refresh.ttl")),
			CreatedIP: &input.Meta.IPAddress,
		},
		Session: domain.Session{
			ID:         sess.ID,
			ExpiresAt:  now.Add(a.config.GetDay("modules.identity.session.ttl")),
			LastSeenAt: &now,
		},
	}); err != nil {
		slog.ErrorContext(ctx, "failed to rotate refresh token", "error", err)

		return nil, goerror.NewServer(err)
	}

	return &RefreshTokenOutput{
		Token:        access,
		RefreshToken: newRefresh,
	}, nil
}
