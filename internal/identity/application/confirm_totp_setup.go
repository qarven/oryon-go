package application

// import (
// 	"context"

// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/goerror"
// 	"github.com/qarven/oryon-go/internal/pkg/jwt"
// )

// type ConfirmTotpSetupInput struct {
// 	FactorID int64  `validate:"required,gt=0"`
// 	Code     string `validate:"required,len=6|len=7|len=8,numeric"`
// }

// type ConfirmTotpSetupOutput struct {
// 	Factor domain.MfaFactor
// }

// func (a *Application) ConfirmTotpSetup(ctx context.Context, input ConfirmTotpSetupInput) (*ConfirmTotpSetupOutput, error) {
// 	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "ConfirmTotpSetup")
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
// 		return nil, goerror.NewBusiness("mfa factor not found", goerror.CodeNotFound)
// 	}

// 	if factor.UserID != claims.UserID {
// 		return nil, goerror.NewBusiness("factor does not belong to user", goerror.CodeForbidden)
// 	}

// 	if factor.Type != domain.MfaFactorTypeTOTP {
// 		return nil, goerror.NewBusiness("factor is not totp", goerror.CodeInvalidInput)
// 	}

// 	if factor.IsRevoked() {
// 		return nil, goerror.NewBusiness("factor revoked", goerror.CodeInvalidInput)
// 	}

// 	if factor.IsVerified() {
// 		return nil, goerror.NewBusiness("factor already verified", goerror.CodeInvalidInput)
// 	}

// 	totp, err := a.repo.GetTotpFactorByFactorID(ctx, factor.ID)
// 	if err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	secret, err := a.mfaEncryption.Decrypt(totp.Secret)
// 	if err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	now := a.clock.Now()
// 	skew := a.config.GetInt("modules.identity.mfa.totp.skew")
// 	if skew == 0 {
// 		skew = 1
// 	}

// 	if !validateTOTP(secret, input.Code, totp.Algorithm, int(totp.Digits), int(totp.Period), skew, now) {
// 		return nil, goerror.NewBusiness("invalid totp code", goerror.CodeUnauthorized)
// 	}

// 	factor.Verify(now)
// 	if err := a.repo.UpdateMfaFactor(ctx, factor); err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	a.logSecurityEvent(ctx, &claims.UserID, "mfa.totp_verified", nil, map[string]any{"factor_id": factor.ID})

// 	return &ConfirmTotpSetupOutput{Factor: factor}, nil
// }
