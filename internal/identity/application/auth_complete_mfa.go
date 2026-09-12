package application

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type CompleteMfaInput struct {
	FlowID     int64                `validate:"required"`
	Code       string               `validate:"required"`
	FactorType domain.MfaFactorType `validate:"required"`
	Meta       MetaInput            `validate:"required"`
}

type CompleteMfaOutput struct {
	Token          *string
	TokenExpiresIn *int64
	RefreshToken   *string
	User           *domain.User
}

type CompleteMfaLoginData struct {
	Factor       *domain.MfaFactor
	BackupCode   *domain.BackupCode
	Flow         domain.AuthFlow
	Session      domain.Session
	RefreshToken domain.RefreshToken
}

func (a *Application) CompleteMfa(ctx context.Context, input CompleteMfaInput) (*CompleteMfaOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "CompleteMfa")
	defer span.End()

	input.Code = strings.TrimSpace(input.Code)
	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	flow, err := a.repo.GetAuthFlowByID(ctx, input.FlowID)
	if errors.Is(err, domain.ErrAuthFlowNotFound) {
		return nil, goerror.NewBusiness("flow not found", goerror.CodeUnauthorized)
	}

	if err != nil {
		return nil, goerror.NewServer(err)
	}

	now := a.clock.Now()
	if flow.IsExpired(now) {
		return nil, goerror.NewBusiness("flow expired", goerror.CodeUnauthorized)
	}

	if flow.FlowState != domain.AuthFlowStatePendingMFA {
		return nil, goerror.NewBusiness("flow not pending mfa", goerror.CodeUnauthorized)
	}

	if flow.UserID == nil {
		return nil, goerror.NewBusiness("flow has no user", goerror.CodeUnauthorized)
	}

	user, err := a.repo.GetUserByID(ctx, *flow.UserID)
	if errors.Is(err, domain.ErrUserNotFound) {
		// data integrity violation
		return nil, goerror.NewBusiness("user not found", goerror.CodeUnauthorized)
	}

	if err != nil {
		return nil, goerror.NewServer(err)
	}

	// Find relevant factors
	var factor *domain.MfaFactor
	factors, err := a.repo.ListMfaFactorsByUserID(ctx, user.ID, false)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	for _, f := range factors {
		if f.Type == input.FactorType && f.IsVerified() && f.IsActive() {
			tmp := f
			factor = &tmp
			break
		}
	}

	if factor == nil {
		return nil, goerror.NewBusiness("no active factor of requested type", goerror.CodeUnauthorized)
	}

	if factor.IsRevoked() {
		return nil, goerror.NewBusiness("factor is revoked", goerror.CodeForbidden)
	}

	if !factor.IsVerified() {
		return nil, goerror.NewBusiness("factor not verified", goerror.CodeForbidden)
	}

	// Verify code depending on type
	var backupCode *domain.BackupCode
	switch factor.Type {
	case domain.MfaFactorTypeTOTP:
		totp, err := a.repo.GetTotpFactorByFactorID(ctx, factor.ID)
		if errors.Is(err, domain.ErrUserNotFound) {
			// data integrity violation
			return nil, goerror.NewBusiness("user not found", goerror.CodeUnauthorized)
		}

		if err != nil {
			return nil, goerror.NewServer(err)
		}

		secret, err := a.mfaEncryption.Decrypt(totp.Secret)
		if err != nil {
			return nil, goerror.NewServer(err)
		}

		if !a.otp.Validate(input.Code, string(secret), now) {
			slog.WarnContext(ctx, "invalid totp code", "user_id", user.ID, "mfa_id", factor.ID)
			return nil, goerror.NewBusiness("invalid otp code", goerror.CodeUnauthorized)
		}

		factor.LastUsedAt = &now

	case domain.MfaFactorTypeBackupCode:
		codes, err := a.repo.ListBackupCodesByUserID(ctx, user.ID)
		if err != nil {
			return nil, goerror.NewServer(err)
		}

		var matched *domain.BackupCode
		for _, c := range codes {
			if a.bcrypt.Verify(string(c.CodeHash), input.Code) {
				tmp := c
				matched = &tmp
				break
			}
		}

		if matched == nil {
			return nil, goerror.NewBusiness("invalid backup code", goerror.CodeUnauthorized)
		}

		matched.UsedAt = &now
		backupCode = matched

	default:
		return nil, goerror.NewBusiness("unsupported factor type", goerror.CodeInvalidInput)
	}

	access, refresh, err := a.issueTokens(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	accessHash, err := a.sha256.Hash(access)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash access token", "error", err)
		return nil, goerror.NewServer(err)
	}

	refreshHash, err := a.sha256.Hash(refresh)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash refresh token", "error", err)
		return nil, goerror.NewServer(err)
	}

	session := domain.Session{
		ID:            a.uid.Generate(),
		UserID:        user.ID,
		TokenHash:     accessHash,
		CreatedAt:     now,
		ExpiresAt:     now.Add(a.config.GetDay("modules.identity.session.ttl")),
		IPAddress:     &input.Meta.IPAddress,
		UserAgent:     &input.Meta.UserAgent,
		MFAVerifiedAt: &now,
		LastSeenAt:    &now,
	}

	flow.CompletedAt = &now
	flow.FlowState = domain.AuthFlowStateCompleted

	var factorData *domain.MfaFactor
	if factor.Type == domain.MfaFactorTypeTOTP {
		factorData = factor
	}

	if err := a.repo.CompleteMfaLogin(ctx, CompleteMfaLoginData{
		Factor:     factorData,
		BackupCode: backupCode,
		Flow:       *flow,
		Session:    session,
		RefreshToken: domain.RefreshToken{
			ID:        a.uid.Generate(),
			SessionID: session.ID,
			TokenHash: refreshHash,
			IssuedAt:  now,
			ExpiresAt: now.Add(a.config.GetDay("modules.identity.jwt.refresh.ttl")),
			CreatedIP: &input.Meta.IPAddress,
		},
	}); err != nil {
		slog.ErrorContext(ctx, "failed to complete mfa login", "error", err)
		return nil, goerror.NewServer(err)
	}

	a.logSecurityEvent(
		&user.ID,
		domain.SecurityEventTypeLoginSuccess,
		input.Meta,
		map[string]any{"method": "mfa", "flow_id": flow.ID, "factor_type": factor.Type, "factor_id": factor.ID},
	)

	tokenExpiresIn := int64(a.config.GetMinute("modules.identity.jwt.access.ttl").Seconds())

	return &CompleteMfaOutput{
		Token:          &access,
		TokenExpiresIn: &tokenExpiresIn,
		RefreshToken:   &refresh,
		User:           user,
	}, nil
}
