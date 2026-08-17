package application

import (
	"context"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

type GenerateRecoveryCodesInput struct {
	Count int32 `validate:"required,gte=1,lte=20"`
}

type GenerateRecoveryCodesOutput struct {
	Codes     []string
	Count     int32
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (a *Application) GenerateRecoveryCodes(ctx context.Context, input GenerateRecoveryCodesInput) (*GenerateRecoveryCodesOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "GenerateRecoveryCodes")
	defer span.End()

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	claims := jwt.GetAuth(ctx)
	if claims == nil {
		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
	}

	if input.Count == 0 {
		input.Count = 10
	}

	// Require MFA verified? For now allow

	// Delete old codes? Or keep? We'll delete old unused to regenerate
	// Keep old? For simplicity we revoke old by deleting
	_, _ = a.repo.DeleteBackupCodesByUserID(ctx, claims.UserID)

	now := a.clock.Now()
	var codes []domain.BackupCode
	var plaintexts []string

	for i := int32(0); i < input.Count; i++ {
		plain, err := generateBackupCode()
		if err != nil {
			return nil, goerror.NewServer(err)
		}

		hash, err := a.argon2id.Hash(plain)
		if err != nil {
			return nil, goerror.NewServer(err)
		}

		id := a.uid.Generate()
		bc, _ := domain.NewBackupCode(id, claims.UserID, hash, now)
		if bc != nil {
			codes = append(codes, *bc)
			plaintexts = append(plaintexts, plain)
		}
	}

	if err := a.repo.CreateBackupCodes(ctx, codes); err != nil {
		return nil, goerror.NewServer(err)
	}

	expires := now.Add(30 * 24 * time.Hour)

	a.logSecurityEvent(ctx, &claims.UserID, "mfa.recovery_codes_generated", nil, nil, map[string]any{"count": input.Count})

	return &GenerateRecoveryCodesOutput{
		Codes:     plaintexts,
		Count:     int32(len(plaintexts)),
		CreatedAt: now,
		ExpiresAt: expires,
	}, nil
}
