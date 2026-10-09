package application

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type CompleteLoginMfaInput struct {
	FlowID     domain.ID            `validate:"required"`
	Code       string               `validate:"required"`
	FactorType domain.MfaFactorType `validate:"required"`
	Meta       MetaInput            `validate:"required"`
}

type CompleteLoginMfaOutput struct {
	Token          string
	TokenExpiresIn int64
	RefreshToken   string
	User           domain.User
}

type CompleteMfaLoginData struct {
	Factor       *domain.MfaFactor
	BackupCode   *domain.BackupCode
	Flow         domain.AuthFlow
	Session      domain.Session
	RefreshToken domain.RefreshToken
}

func (a *Application) CompleteLoginMfa(
	ctx context.Context,
	input CompleteLoginMfaInput,
) (*CompleteLoginMfaOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "CompleteLoginMfa")
	defer span.End()

	input.Code = strings.TrimSpace(input.Code)

	err := a.validator.Validate(input)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	flow, user, now, err := a.loadMfaLoginFlow(ctx, input.FlowID)
	if err != nil {
		return nil, err
	}

	factor, err := a.findLoginMfaFactor(ctx, user.ID, input.FactorType)
	if err != nil {
		return nil, err
	}

	backupCode, err := a.verifyLoginMfaCode(ctx, factor, user.ID, input.Code, now)
	if err != nil {
		return nil, err
	}

	issue, err := a.issueTokens(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	out, err := a.finishMfaLogin(ctx, mfaLoginFinishData{
		Flow:       flow,
		User:       user,
		Factor:     factor,
		BackupCode: backupCode,
		Meta:       input.Meta,
		Now:        now,
		issue:      issue,
	})
	if err != nil {
		return nil, err
	}

	a.securityEvent(domain.SecurityEventTypeLoginSuccess).
		ForUser(&user.ID).
		WithMeta(input.Meta).
		With("method", "mfa").
		With("flow_id", flow.ID).
		With("factor_type", factor.Type).
		With("factor_id", factor.ID).
		Emit(ctx)

	return out, nil
}

func (a *Application) loadMfaLoginFlow(
	ctx context.Context,
	flowID domain.ID,
) (*domain.AuthFlow, *domain.User, time.Time, error) {
	flow, err := a.repo.GetAuthFlowByID(ctx, flowID)
	if errors.Is(err, domain.ErrAuthFlowNotFound) {
		slog.WarnContext(ctx, "auth flow not found")

		return nil, nil, time.Time{}, goerror.NewBusiness("flow not found", goerror.CodeUnauthorized)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get auth flow", "error", err)

		return nil, nil, time.Time{}, goerror.NewServer(err)
	}

	now := a.clock.Now()
	if flow.IsExpired(now) {
		slog.WarnContext(ctx, "auth flow already expired")

		return nil, nil, time.Time{}, goerror.NewBusiness("flow expired", goerror.CodeUnauthorized)
	}

	if flow.FlowState != domain.AuthFlowStatePendingMFA {
		slog.WarnContext(ctx, "auth flow state not pending mfa", "flow_state", flow.FlowState)

		return nil, nil, time.Time{}, goerror.NewBusiness("flow not pending mfa", goerror.CodeUnauthorized)
	}

	if flow.UserID == nil {
		slog.WarnContext(ctx, "auth flow has no user")

		return nil, nil, time.Time{}, goerror.NewBusiness("flow has no user", goerror.CodeUnauthorized)
	}

	user, err := a.repo.GetUserByID(ctx, *flow.UserID)
	if errors.Is(err, domain.ErrUserNotFound) {
		// data integrity violation
		slog.ErrorContext(
			ctx,
			"data integrity violation: auth flow user not found",
			"flow_id",
			flow.ID,
			"user_id",
			*flow.UserID,
		)

		return nil, nil, time.Time{}, goerror.NewServer(err)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "error", err)

		return nil, nil, time.Time{}, goerror.NewServer(err)
	}

	return flow, user, now, nil
}

func (a *Application) findLoginMfaFactor(
	ctx context.Context,
	userID domain.ID,
	factorType domain.MfaFactorType,
) (*domain.MfaFactor, error) {
	factors, err := a.repo.ListMfaFactorsByUserID(ctx, userID, false)
	if err != nil {
		slog.ErrorContext(ctx, "failed to list mfa factors by user id", "error", err)

		return nil, goerror.NewServer(err)
	}

	var factor *domain.MfaFactor

	for _, f := range factors {
		if f.Type == factorType && f.IsVerified() && f.IsActive() {
			tmp := f
			factor = &tmp

			break
		}
	}

	if factor == nil {
		slog.WarnContext(
			ctx,
			"no active mfa factor of requested type",
			"user_id",
			userID,
			"factor_type",
			factorType,
		)

		return nil, goerror.NewBusiness("no active factor of requested type", goerror.CodeUnauthorized)
	}

	if factor.IsRevoked() {
		slog.WarnContext(ctx, "mfa factor is revoked", "user_id", userID, "mfa_id", factor.ID)

		return nil, goerror.NewBusiness("factor is revoked", goerror.CodeForbidden)
	}

	if !factor.IsVerified() {
		slog.WarnContext(ctx, "mfa factor not verified", "user_id", userID, "mfa_id", factor.ID)

		return nil, goerror.NewBusiness("factor not verified", goerror.CodeForbidden)
	}

	return factor, nil
}

func (a *Application) verifyLoginMfaCode(
	ctx context.Context,
	factor *domain.MfaFactor,
	userID domain.ID,
	code string,
	now time.Time,
) (*domain.BackupCode, error) {
	switch factor.Type {
	case domain.MfaFactorTypeTOTP:
		return nil, a.verifyLoginTotpCode(ctx, factor, userID, code, now)
	case domain.MfaFactorTypeBackupCode:
		return a.verifyLoginBackupCode(ctx, userID, code, now)
	default:
		slog.WarnContext(
			ctx,
			"unsupported mfa factor type",
			"user_id",
			userID,
			"mfa_id",
			factor.ID,
			"factor_type",
			factor.Type,
		)

		return nil, goerror.NewBusiness("unsupported factor type", goerror.CodeInvalidInput)
	}
}

func (a *Application) verifyLoginTotpCode(
	ctx context.Context,
	factor *domain.MfaFactor,
	userID domain.ID,
	code string,
	now time.Time,
) error {
	totp, err := a.repo.GetTotpFactorByFactorID(ctx, factor.ID)
	if errors.Is(err, domain.ErrUserNotFound) {
		// data integrity violation
		slog.ErrorContext(
			ctx,
			"data integrity violation: totp factor not found",
			"user_id",
			userID,
			"mfa_id",
			factor.ID,
		)

		return goerror.NewServer(err)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get totp factor by factor id", "mfa_id", factor.ID, "error", err)

		return goerror.NewServer(err)
	}

	secret, err := a.mfaEncryption.Decrypt(totp.Secret)
	if err != nil {
		slog.ErrorContext(ctx, "failed to decrypt totp secret", "mfa_id", factor.ID, "error", err)

		return goerror.NewServer(err)
	}

	if !a.otp.Validate(code, string(secret), now) {
		slog.WarnContext(ctx, "invalid totp code", "user_id", userID, "mfa_id", factor.ID)

		return goerror.NewBusiness("invalid otp code", goerror.CodeUnauthorized)
	}

	factor.LastUsedAt = &now

	return nil
}

func (a *Application) verifyLoginBackupCode(
	ctx context.Context,
	userID domain.ID,
	code string,
	now time.Time,
) (*domain.BackupCode, error) {
	codes, err := a.repo.ListBackupCodesByUserID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to list backup codes by user id", "user_id", userID, "error", err)

		return nil, goerror.NewServer(err)
	}

	for _, backupCode := range codes {
		if backupCode.IsUsed() {
			continue
		}

		if a.argon2id.Verify(string(backupCode.CodeHash), code) {
			matched := backupCode
			matched.UsedAt = &now

			return &matched, nil
		}
	}

	slog.WarnContext(ctx, "invalid backup code", "user_id", userID)

	return nil, goerror.NewBusiness("invalid backup code", goerror.CodeUnauthorized)
}

type mfaLoginFinishData struct {
	Flow       *domain.AuthFlow
	User       *domain.User
	Factor     *domain.MfaFactor
	BackupCode *domain.BackupCode
	Meta       MetaInput
	Now        time.Time
	issue      *issueToken
}

func (a *Application) finishMfaLogin(
	ctx context.Context,
	data mfaLoginFinishData,
) (*CompleteLoginMfaOutput, error) {
	accessHash, err := a.sha256.Hash(data.issue.accessToken)
	if err != nil {
		slog.ErrorContext(
			ctx,
			"failed to hash access token",
			"user_id",
			data.User.ID,
			"flow_id",
			data.Flow.ID,
			"error",
			err,
		)

		return nil, goerror.NewServer(err)
	}

	refreshHash, err := a.sha256.Hash(data.issue.refreshToken)
	if err != nil {
		slog.ErrorContext(
			ctx,
			"failed to hash refresh token",
			"user_id",
			data.User.ID,
			"flow_id",
			data.Flow.ID,
			"error",
			err,
		)

		return nil, goerror.NewServer(err)
	}

	session := domain.Session{
		ID:            domain.IDFrom(a.uuid.Generate()),
		UserID:        data.User.ID,
		TokenHash:     accessHash,
		CreatedAt:     data.Now,
		ExpiresAt:     data.Now.Add(a.config.GetDay("modules.identity.session.ttl")),
		IPAddress:     &data.Meta.IPAddress,
		UserAgent:     &data.Meta.UserAgent,
		MFAVerifiedAt: &data.Now,
		LastSeenAt:    &data.Now,
	}

	err = a.persistMfaLogin(ctx, data, session, refreshHash)
	if err != nil {
		return nil, err
	}

	tokenExpiresIn := int64(a.config.GetMinute("modules.identity.jwt.access.ttl").Seconds())

	return &CompleteLoginMfaOutput{
		Token:          data.issue.accessToken,
		TokenExpiresIn: tokenExpiresIn,
		RefreshToken:   data.issue.refreshToken,
		User:           *data.User,
	}, nil
}

func (a *Application) persistMfaLogin(
	ctx context.Context,
	data mfaLoginFinishData,
	session domain.Session,
	refreshHash []byte,
) error {
	data.Flow.CompletedAt = &data.Now
	data.Flow.FlowState = domain.AuthFlowStateCompleted

	var factorData *domain.MfaFactor
	if data.Factor.Type == domain.MfaFactorTypeTOTP {
		factorData = data.Factor
	}

	err := a.repo.CompleteMfaLogin(ctx, CompleteMfaLoginData{
		Factor:     factorData,
		BackupCode: data.BackupCode,
		Flow:       *data.Flow,
		Session:    session,
		RefreshToken: domain.RefreshToken{
			ID:        domain.IDFrom(a.uuid.Generate()),
			SessionID: session.ID,
			TokenHash: refreshHash,
			IssuedAt:  data.Now,
			ExpiresAt: data.Now.Add(a.config.GetDay("modules.identity.jwt.refresh.ttl")),
			CreatedIP: &data.Meta.IPAddress,
		},
	})
	if err != nil {
		slog.ErrorContext(
			ctx,
			"failed to complete mfa login",
			"flow_id",
			data.Flow.ID,
			"user_id",
			data.User.ID,
			"session_id",
			session.ID,
			"error",
			err,
		)

		return goerror.NewServer(err)
	}

	return nil
}
