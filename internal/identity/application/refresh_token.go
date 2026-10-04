package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
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

// ErrSessionUserMismatch is returned when a refresh token session belongs
// to a different user than the token claims.
var ErrSessionUserMismatch = errors.New("session user does not match token user")

func (a *Application) RefreshToken(ctx context.Context, input RefreshTokenInput) (*RefreshTokenOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "RefreshToken")
	defer span.End()

	err := a.validator.Validate(input)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	claims, storedToken, now, err := a.loadValidRefreshToken(ctx, input.RefreshToken)
	if err != nil {
		return nil, err
	}

	sess, err := a.loadRefreshSession(ctx, storedToken, claims.UserID, now)
	if err != nil {
		return nil, err
	}

	issue, err := a.issueTokens(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}

	return a.rotateRefreshToken(ctx, refreshRotationData{
		StoredToken: storedToken,
		Session:     sess,
		Now:         now,
		Access:      issue.accessToken,
		NewRefresh:  issue.refreshToken,
		Meta:        input.Meta,
	})
}

type refreshRotationData struct {
	StoredToken *domain.RefreshToken
	Session     *domain.Session
	Now         time.Time
	Access      string
	NewRefresh  string
	Meta        MetaInput
}

// rotateRefreshToken hashes the new refresh token, swaps it with the old
// one, and refreshes the session.
func (a *Application) rotateRefreshToken(
	ctx context.Context,
	data refreshRotationData,
) (*RefreshTokenOutput, error) {
	newID := a.uid.Generate()

	newHash, err := a.sha256.Hash(data.NewRefresh)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash new refresh token", "error", err)

		return nil, goerror.NewServer(err)
	}

	err = a.repo.RotateRefreshToken(ctx, RotateRefreshTokenData{
		OldRefreshToken: domain.RefreshToken{
			ID:         data.StoredToken.ID,
			SessionID:  data.StoredToken.SessionID,
			RevokedAt:  &data.Now,
			ReplacedBy: &newID,
		},
		NewRefreshToken: domain.RefreshToken{
			ID:        newID,
			SessionID: data.Session.ID,
			TokenHash: newHash,
			IssuedAt:  data.Now,
			ExpiresAt: data.Now.Add(a.config.GetDay("modules.identity.jwt.refresh.ttl")),
			CreatedIP: &data.Meta.IPAddress,
		},
		Session: domain.Session{
			ID:         data.Session.ID,
			ExpiresAt:  data.Now.Add(a.config.GetDay("modules.identity.session.ttl")),
			LastSeenAt: &data.Now,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to rotate refresh token", "error", err)

		return nil, goerror.NewServer(err)
	}

	return &RefreshTokenOutput{
		Token:        data.Access,
		RefreshToken: data.NewRefresh,
		ExpiresIn:    int64(a.config.GetMinute("modules.identity.jwt.access.ttl").Seconds()),
	}, nil
}

// loadValidRefreshToken verifies the presented refresh token and returns
// its claims with the stored, unexpired, unrevoked token row.
func (a *Application) loadValidRefreshToken(
	ctx context.Context,
	token string,
) (jwt.Claims, *domain.RefreshToken, time.Time, error) {
	claims, err := a.refreshJWT.Verify(token)
	if err != nil {
		slog.WarnContext(ctx, "invalid or expired refresh token", "error", err)

		return jwt.Claims{}, nil, time.Time{}, goerror.NewBusiness(
			"invalid or expired refresh token",
			goerror.CodeUnauthorized,
		)
	}

	hashBytes, err := a.sha256.Hash(token)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash refresh token", "error", err)

		return jwt.Claims{}, nil, time.Time{}, goerror.NewServer(err)
	}

	storedToken, err := a.repo.GetRefreshTokenByHash(ctx, hashBytes)
	if errors.Is(err, domain.ErrRefreshTokenNotFound) {
		slog.WarnContext(ctx, "refresh token not found")

		return jwt.Claims{}, nil, time.Time{}, goerror.NewBusiness(
			"refresh token not found",
			goerror.CodeUnauthorized,
		)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get refresh token by hash", "error", err)

		return jwt.Claims{}, nil, time.Time{}, goerror.NewServer(err)
	}

	now := a.clock.Now()

	if storedToken.IsRevoked() {
		slog.WarnContext(ctx, "refresh token already revoked")

		return jwt.Claims{}, nil, time.Time{}, goerror.NewBusiness(
			"refresh token revoked",
			goerror.CodeUnauthorized,
		)
	}

	if storedToken.IsExpired(now) {
		slog.WarnContext(ctx, "refresh token already expired")

		return jwt.Claims{}, nil, time.Time{}, goerror.NewBusiness(
			"refresh token expired",
			goerror.CodeUnauthorized,
		)
	}

	return claims, storedToken, now, nil
}

// loadRefreshSession returns the live session for a refresh token,
// ensuring it belongs to the token user.
func (a *Application) loadRefreshSession(
	ctx context.Context,
	storedToken *domain.RefreshToken,
	userID int64,
	now time.Time,
) (*domain.Session, error) {
	sess, err := a.repo.GetSessionByID(ctx, storedToken.SessionID)
	if errors.Is(err, domain.ErrSessionNotFound) {
		slog.ErrorContext(
			ctx,
			"data integrity violation: refresh token session not found",
			"session_id",
			storedToken.SessionID,
		)

		return nil, goerror.NewServer(err)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get session by id", "session_id", storedToken.SessionID, "error", err)

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

	if sess.UserID != userID {
		slog.ErrorContext(ctx, "data integrity violation: session user does not match refresh token user",
			"session_id", sess.ID,
			"session_user_id", sess.UserID,
			"token_user_id", userID,
		)
		mismatchErr := fmt.Errorf(
			"%w: session user %d does not match token user %d",
			ErrSessionUserMismatch,
			sess.UserID,
			userID,
		)

		return nil, goerror.NewServer(mismatchErr)
	}

	return sess, nil
}
