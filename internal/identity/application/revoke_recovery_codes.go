package application

// import (
// 	"context"

// 	"github.com/qarven/oryon-go/internal/pkg/goerror"
// 	"github.com/qarven/oryon-go/internal/pkg/jwt"
// )

// type RevokeRecoveryCodesInput struct{}

// type RevokeRecoveryCodesOutput struct {
// 	RevokedCount int64
// }

// func (a *Application) RevokeRecoveryCodes(ctx context.Context, input RevokeRecoveryCodesInput) (*RevokeRecoveryCodesOutput, error) {
// 	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "RevokeRecoveryCodes")
// 	defer span.End()

// 	claims := jwt.GetAuth(ctx)
// 	if claims == nil {
// 		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
// 	}

// 	count, err := a.repo.DeleteBackupCodesByUserID(ctx, claims.UserID)
// 	if err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	a.logSecurityEvent(ctx, &claims.UserID, "mfa.recovery_codes_revoked", nil, map[string]any{"count": count})

// 	return &RevokeRecoveryCodesOutput{RevokedCount: count}, nil
// }
