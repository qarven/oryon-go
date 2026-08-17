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
	IPAddress    *string
	UserAgent    *string
}

type RefreshTokenOutput struct {
	Token        string
	RefreshToken string
	Session      domain.Session
}

func (a *Application) RefreshToken(ctx context.Context, input RefreshTokenInput) (*RefreshTokenOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "RefreshToken")
	defer span.End()

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	claims, err := a.refreshJWT.Verify(input.RefreshToken)
	if err != nil {
		return nil, goerror.NewBusiness("invalid or expired refresh token", goerror.CodeUnauthorized)
	}

	hash := hashToken(input.RefreshToken)
	rt, err := a.repo.GetRefreshTokenByHash(ctx, hash)
	if errors.Is(err, domain.ErrRefreshTokenNotFound) {
		return nil, goerror.NewBusiness("refresh token not found", goerror.CodeUnauthorized)
	}

	if err != nil {
		return nil, goerror.NewServer(err)
	}

	now := a.clock.Now()
	if rt.IsRevoked() {
		return nil, goerror.NewBusiness("refresh token revoked", goerror.CodeUnauthorized)
	}

	if rt.IsExpired(now) {
		return nil, goerror.NewBusiness("refresh token expired", goerror.CodeUnauthorized)
	}

	sess, err := a.repo.GetSessionByID(ctx, rt.SessionID)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	if sess.IsRevoked() {
		return nil, goerror.NewBusiness("session revoked", goerror.CodeUnauthorized)
	}

	if sess.IsExpired(now) {
		return nil, goerror.NewBusiness("session expired", goerror.CodeUnauthorized)
	}

	if sess.UserID != claims.UserID {
		return nil, goerror.NewBusiness("token user mismatch", goerror.CodeUnauthorized)
	}

	// Rotate refresh token: revoke old, issue new
	_ = rt.Revoke(now)
	_ = a.repo.UpdateRefreshToken(ctx, rt)

	primaryEmail, _ := a.getPrimaryEmail(ctx, sess.UserID)
	if primaryEmail == "" {
		primaryEmail = claims.UserEmail
	}

	access, newRefresh, err := a.issueTokens(sess.UserID, primaryEmail)
	if err != nil {
		return nil, err
	}

	// Create new refresh token record with replaced_by link
	newID := a.uid.Generate()
	newHash := hashToken(newRefresh)
	expires := now.Add(a.config.GetDay("modules.identity.jwt.refresh.ttl"))
	if expires.IsZero() || expires.Before(now) {
		expires = now.Add(7 * 24 * time.Hour)
	}

	newRT, _ := domain.NewRefreshToken(newID, sess.ID, newHash, now, expires, input.IPAddress)
	if newRT != nil {
		// link old to new
		rt.ReplacedBy = &newID
		_ = a.repo.UpdateRefreshToken(ctx, rt)
		_ = a.repo.CreateRefreshToken(ctx, *newRT)
	}

	// Update session last_seen
	sess.Touch(now)
	_ = a.repo.UpdateSession(ctx, sess)

	// Optionally new session token hash? Keep same session but rotate access hash? We create new session hash for new access? But session token hash is fixed to first access token; we could update it? For simplicity keep session token hash unchanged, but issue new access token with new hash not stored. Alternative store new token hash as session's token? We keep old.

	return &RefreshTokenOutput{
		Token:        access,
		RefreshToken: newRefresh,
		Session:      sess,
	}, nil
}
