package application

// import (
// 	"context"

// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/goerror"
// 	"github.com/qarven/oryon-go/internal/pkg/jwt"
// )

// type RevokeSessionInput struct {
// 	SessionID int64 `validate:"required,gt=0"`
// }

// type RevokeSessionOutput struct{}

// func (a *Application) RevokeSession(ctx context.Context, input RevokeSessionInput) (*RevokeSessionOutput, error) {
// 	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "RevokeSession")
// 	defer span.End()

// 	if err := a.validator.Validate(input); err != nil {
// 		return nil, goerror.NewInvalidInput(err)
// 	}

// 	claims := jwt.GetAuth(ctx)
// 	if claims == nil {
// 		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
// 	}

// 	sess, err := a.repo.GetSessionByID(ctx, input.SessionID)
// 	if err != nil {
// 		if err == domain.ErrSessionNotFound {
// 			return nil, goerror.NewBusiness("session not found", goerror.CodeNotFound)
// 		}

// 		return nil, goerror.NewServer(err)
// 	}

// 	if sess.UserID != claims.UserID {
// 		return nil, goerror.NewBusiness("session does not belong to user", goerror.CodeForbidden)
// 	}

// 	if sess.IsRevoked() {
// 		return nil, goerror.NewBusiness("session already revoked", goerror.CodeInvalidInput)
// 	}

// 	now := a.clock.Now()
// 	if err := a.repo.RevokeSession(ctx, sess.ID, toPgTimestamptz(now)); err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	_, _ = a.repo.RevokeRefreshTokensBySessionID(ctx, sess.ID, toPgTimestamptz(now))

// 	a.logSecurityEvent(ctx, &claims.UserID, "session.revoked", nil, nil, map[string]any{"session_id": sess.ID})

// 	return &RevokeSessionOutput{}, nil
// }
