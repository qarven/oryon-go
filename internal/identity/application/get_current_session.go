package application

// import (
// 	"context"

// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/goerror"
// 	"github.com/qarven/oryon-go/internal/pkg/jwt"
// )

// type GetCurrentSessionInput struct{}

// type GetCurrentSessionOutput struct {
// 	Session domain.Session
// }

// func (a *Application) GetCurrentSession(ctx context.Context, input GetCurrentSessionInput) (*GetCurrentSessionOutput, error) {
// 	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "GetCurrentSession")
// 	defer span.End()

// 	claims := jwt.GetAuth(ctx)
// 	if claims == nil {
// 		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
// 	}

// 	// Try to find session via listing user sessions and picking active one
// 	// Since we don't have session id in claims, we list and return most recent active
// 	sessions, err := a.repo.ListSessionsByUserID(ctx, claims.UserID, false, false)
// 	if err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	if len(sessions) == 0 {
// 		return nil, goerror.NewBusiness("no active session", goerror.CodeNotFound)
// 	}

// 	// Return most recent (first, ordered by created_at DESC)
// 	sess := sessions[0]

// 	// Touch
// 	now := a.clock.Now()
// 	sess.Touch(now)
// 	_ = a.repo.TouchSession(ctx, sess.ID, toPgTimestamptz(now))

// 	return &GetCurrentSessionOutput{Session: sess}, nil
// }
