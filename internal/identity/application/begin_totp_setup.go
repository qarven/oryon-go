package application

import (
	"context"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

type BeginTotpSetupInput struct {
	Name      string               `validate:"required"`
	Algorithm domain.TotpAlgorithm `validate:"omitempty"`
	Digits    int32                `validate:"omitempty,oneof=6 8"`
	Period    int32                `validate:"omitempty,gt=0"`
	Issuer    *string              `validate:"omitempty"`
}

type BeginTotpSetupOutput struct {
	Factor     domain.MfaFactor
	TotpFactor domain.TotpFactor
	Secret     string
	URI        string
}

func (a *Application) BeginTotpSetup(ctx context.Context, input BeginTotpSetupInput) (*BeginTotpSetupOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "BeginTotpSetup")
	defer span.End()

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	claims := jwt.GetAuth(ctx)
	if claims == nil {
		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
	}

	userID := claims.UserID

	// Defaults
	algo := input.Algorithm
	if algo == domain.TotpAlgorithmUnknown {
		algo = domain.TotpAlgorithmSHA1
	}

	if !algo.IsValid() {
		return nil, goerror.NewBusiness("invalid totp algorithm", goerror.CodeInvalidInput)
	}

	digits := input.Digits
	if digits == 0 {
		digits = 6
	}

	period := input.Period
	if period == 0 {
		period = int32(a.config.GetInt("modules.identity.mfa.totp.period"))
		if period == 0 {
			period = 30
		}
	}

	issuer := a.config.GetString("modules.identity.mfa.totp.issuer")
	if input.Issuer != nil && *input.Issuer != "" {
		issuer = *input.Issuer
	}

	if issuer == "" {
		issuer = "ORYON"
	}

	// Check existing unverified factors? Allow multiple but prevent duplicate name?
	// For simplicity allow

	now := a.clock.Now()
	secretRaw, err := generateTOTPSecret(20)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	secretB32 := base32EncodeNoPadding(secretRaw)

	encSecret, err := a.mfaEncryption.Encrypt(secretRaw)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	factorID := a.uid.Generate()
	factor, err := domain.NewMfaFactor(factorID, userID, domain.MfaFactorTypeTOTP, input.Name, now)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	if err := a.repo.CreateMfaFactor(ctx, *factor); err != nil {
		return nil, goerror.NewServer(err)
	}

	totp, err := domain.NewTotpFactor(factorID, encSecret, algo, int16(digits), int16(period), now)
	if err != nil {
		// rollback factor?
		return nil, goerror.NewServer(err)
	}

	if err := a.repo.CreateTotpFactor(ctx, *totp); err != nil {
		return nil, goerror.NewServer(err)
	}

	// Build otpauth URI
	// Account is primary email
	account := claims.UserEmail
	if pe, err := a.repo.GetPrimaryUserEmailByUserID(ctx, userID); err == nil {
		account = pe.Email
	}

	uri := buildOTPAuthURI(issuer, account, secretB32, algo, int(digits), int(period))

	return &BeginTotpSetupOutput{
		Factor:     *factor,
		TotpFactor: *totp,
		Secret:     secretB32,
		URI:        uri,
	}, nil
}
