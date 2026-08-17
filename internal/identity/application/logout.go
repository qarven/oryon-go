package application

import (
	"context"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

type LogoutInput struct {
	SessionID           *int64 `validate:"omitempty,gt=0"`
	RevokeRefreshTokens bool
}

type LogoutOutput struct{}

func (a *Application) Logout(ctx context.Context, input LogoutInput) (*LogoutOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "Logout")
	defer span.End()

	claims := jwt.GetAuth(ctx)
	if claims == nil {
		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
	}

	var targetID int64
	if input.SessionID != nil && *input.SessionID != 0 {
		targetID = *input.SessionID
	} else {
		sessions, err := a.repo.ListSessionsByUserID(ctx, claims.UserID, false, false)
		if err != nil {
			return nil, goerror.NewServer(err)
		}

		if len(sessions) == 0 {
			return nil, goerror.NewBusiness("no active session", goerror.CodeNotFound)
		}

		targetID = sessions[0].ID
	}

	sess, err := a.repo.GetSessionByID(ctx, targetID)
	if err != nil {
		if err == domain.ErrSessionNotFound {
			return nil, goerror.NewBusiness("session not found", goerror.CodeNotFound)
		}

		return nil, goerror.NewServer(err)
	}

	if sess.UserID != claims.UserID {
		return nil, goerror.NewBusiness("session does not belong to user", goerror.CodeForbidden)
	}

	now := a.clock.Now()
	if !sess.IsRevoked() {
		if err := a.repo.RevokeSession(ctx, sess.ID, toPgTimestamptz(now)); err != nil {
			return nil, goerror.NewServer(err)
		}
	}

	if input.RevokeRefreshTokens {
		_, _ = a.repo.RevokeRefreshTokensBySessionID(ctx, sess.ID, toPgTimestamptz(now))
	}

	a.logSecurityEvent(ctx, &claims.UserID, "logout", nil, nil, map[string]any{"session_id": sess.ID})

	return &LogoutOutput{}, nil
}
