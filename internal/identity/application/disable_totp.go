package application

// import (
// 	"context"
// 	"errors"

// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/goerror"
// 	"github.com/qarven/oryon-go/internal/pkg/jwt"
// )

// type DisableTotpInput struct {
// 	FactorID        int64   `validate:"required,gt=0"`
// 	CurrentPassword *string `validate:"omitempty"`
// }

// type DisableTotpOutput struct{}

// func (a *Application) DisableTotp(ctx context.Context, input DisableTotpInput) (*DisableTotpOutput, error) {
// 	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "DisableTotp")
// 	defer span.End()

// 	if err := a.validator.Validate(input); err != nil {
// 		return nil, goerror.NewInvalidInput(err)
// 	}

// 	claims := jwt.GetAuth(ctx)
// 	if claims == nil {
// 		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
// 	}

// 	factor, err := a.repo.GetMfaFactorByID(ctx, input.FactorID)
// 	if err != nil {
// 		return nil, goerror.NewBusiness("factor not found", goerror.CodeNotFound)
// 	}

// 	if factor.UserID != claims.UserID {
// 		return nil, goerror.NewBusiness("factor does not belong to user", goerror.CodeForbidden)
// 	}

// 	if factor.IsRevoked() {
// 		return nil, goerror.NewBusiness("factor already revoked", goerror.CodeInvalidInput)
// 	}

// 	// Optionally require current password
// 	if input.CurrentPassword != nil && *input.CurrentPassword != "" {
// 		cred, err := a.repo.GetPasswordCredentialByUserID(ctx, claims.UserID)
// 		if err != nil {
// 			if errors.Is(err, domain.ErrPasswordCredentialNotFound) {
// 				return nil, goerror.NewBusiness("password credential not found", goerror.CodeNotFound)
// 			}

// 			return nil, goerror.NewServer(err)
// 		}

// 		if !a.argon2id.Verify(cred.Password, *input.CurrentPassword) {
// 			return nil, goerror.NewBusiness("current password is incorrect", goerror.CodeUnauthorized)
// 		}
// 	}

// 	now := a.clock.Now()
// 	if err := factor.Revoke(now); err != nil {
// 		return nil, goerror.NewBusiness(err.Error(), goerror.CodeInvalidInput)
// 	}

// 	if err := a.repo.UpdateMfaFactor(ctx, factor); err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	// Also delete totp row? Keep for audit but we can delete
// 	_ = a.repo.DeleteTotpFactor(ctx, factor.ID)

// 	a.logSecurityEvent(ctx, &claims.UserID, "mfa.totp_disabled", nil, map[string]any{"factor_id": factor.ID})

// 	return &DisableTotpOutput{}, nil
// }
