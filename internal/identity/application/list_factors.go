package application

import (
	"context"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

type ListFactorsInput struct {
	IncludeRevoked bool
}

type ListFactorsOutput struct {
	Factors              []domain.MfaFactor
	TotpFactors          []domain.TotpFactor
	Passkeys             []domain.Passkey
	BackupCodesRemaining int32
}

func (a *Application) ListFactors(ctx context.Context, input ListFactorsInput) (*ListFactorsOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "ListFactors")
	defer span.End()

	claims := jwt.GetAuth(ctx)
	if claims == nil {
		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
	}

	factors, err := a.repo.ListMfaFactorsByUserID(ctx, claims.UserID, input.IncludeRevoked)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	var totps []domain.TotpFactor
	for _, f := range factors {
		if f.Type == domain.MfaFactorTypeTOTP {
			if t, err := a.repo.GetTotpFactorByFactorID(ctx, f.ID); err == nil {
				totps = append(totps, t)
			}
		}
	}

	passkeys, err := a.repo.ListPasskeysByUserID(ctx, claims.UserID, input.IncludeRevoked)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	remaining, err := a.repo.CountUnusedBackupCodes(ctx, claims.UserID)
	if err != nil {
		remaining = 0
	}

	return &ListFactorsOutput{
		Factors:              factors,
		TotpFactors:          totps,
		Passkeys:             passkeys,
		BackupCodesRemaining: remaining,
	}, nil
}
