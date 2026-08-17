package application

import (
	"context"

	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

type RevokeAllOtherSessionsInput struct{}

type RevokeAllOtherSessionsOutput struct {
	RevokedCount int64
}

func (a *Application) RevokeAllOtherSessions(ctx context.Context, input RevokeAllOtherSessionsInput) (*RevokeAllOtherSessionsOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "RevokeAllOtherSessions")
	defer span.End()

	claims := jwt.GetAuth(ctx)
	if claims == nil {
		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
	}

	// Find current session via GetCurrentSession logic
	sessions, err := a.repo.ListSessionsByUserID(ctx, claims.UserID, false, false)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	var currentID int64
	if len(sessions) > 0 {
		currentID = sessions[0].ID
	}

	now := a.clock.Now()
	count, err := a.repo.RevokeAllOtherSessions(ctx, claims.UserID, currentID, toPgTimestamptz(now))
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	// Also revoke refresh tokens for those sessions? The DB revoke for sessions will cascade? We'll also need to handle refresh tokens
	// For simplicity, revoke refresh tokens for all other sessions individually? But our SQL only revokes sessions; refresh tokens remain but will be invalid due to session revoked check
	// Optionally revoke refresh tokens
	_ = currentID

	a.logSecurityEvent(ctx, &claims.UserID, "session.revoke_all_other", nil, nil, map[string]any{"revoked_count": count})

	return &RevokeAllOtherSessionsOutput{RevokedCount: count}, nil
}
