package application

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type CompleteMfaInput struct {
	FlowID     string               `validate:"required"`
	Code       string               `validate:"required"`
	FactorType domain.MfaFactorType `validate:"required"`
	FactorID   *int64               `validate:"omitempty"`
	IPAddress  *string              `validate:"omitempty,ip"`
	UserAgent  *string
}

type CompleteMfaOutput struct {
	Token        string
	RefreshToken string
	Session      domain.Session
	User         domain.User
}

func (a *Application) CompleteMfa(ctx context.Context, input CompleteMfaInput) (*CompleteMfaOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "CompleteMfa")
	defer span.End()

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	flowID, err := strconv.ParseInt(input.FlowID, 10, 64)
	if err != nil {
		return nil, goerror.NewBusiness("invalid flow_id", goerror.CodeInvalidInput)
	}

	flow, err := a.repo.GetAuthFlowByID(ctx, flowID)
	if err != nil {
		if errors.Is(err, domain.ErrAuthFlowNotFound) {
			return nil, goerror.NewBusiness("flow not found", goerror.CodeNotFound)
		}

		return nil, goerror.NewServer(err)
	}

	now := a.clock.Now()
	if flow.IsExpired(now) {
		return nil, goerror.NewBusiness("flow expired", goerror.CodeInvalidInput)
	}

	if flow.FlowState != domain.AuthFlowStatePendingMFA {
		return nil, goerror.NewBusiness("flow not pending mfa", goerror.CodeInvalidInput)
	}

	if flow.UserID == nil {
		return nil, goerror.NewBusiness("flow has no user", goerror.CodeInvalidInput)
	}

	userID := *flow.UserID

	user, err := a.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	// Find relevant factors
	var factor *domain.MfaFactor

	if input.FactorID != nil {
		f, err := a.repo.GetMfaFactorByID(ctx, *input.FactorID)
		if err != nil {
			return nil, goerror.NewBusiness("mfa factor not found", goerror.CodeNotFound)
		}

		if f.UserID != userID {
			return nil, goerror.NewBusiness("factor does not belong to user", goerror.CodeForbidden)
		}

		if f.Type != input.FactorType {
			return nil, goerror.NewBusiness("factor type mismatch", goerror.CodeInvalidInput)
		}

		factor = &f
	} else {
		factors, err := a.repo.ListMfaFactorsByUserID(ctx, userID, false)
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
			return nil, goerror.NewBusiness("no active factor of requested type", goerror.CodeNotFound)
		}
	}

	if factor.IsRevoked() {
		return nil, goerror.NewBusiness("factor is revoked", goerror.CodeForbidden)
	}

	if !factor.IsVerified() {
		return nil, goerror.NewBusiness("factor not verified", goerror.CodeInvalidInput)
	}

	// Verify code depending on type
	switch factor.Type {
	case domain.MfaFactorTypeTOTP:
		totp, err := a.repo.GetTotpFactorByFactorID(ctx, factor.ID)
		if err != nil {
			return nil, goerror.NewServer(err)
		}

		secret, err := a.mfaEncryption.Decrypt(totp.Secret)
		if err != nil {
			return nil, goerror.NewServer(err)
		}

		skew := a.config.GetInt("modules.identity.mfa.totp.skew")
		if skew == 0 {
			skew = 1
		}

		if !validateTOTP(secret, input.Code, totp.Algorithm, int(totp.Digits), int(totp.Period), skew, now) {
			return nil, goerror.NewBusiness("invalid totp code", goerror.CodeUnauthorized)
		}

		factor.Touch(now)
		_ = a.repo.UpdateMfaFactor(ctx, *factor)

	case domain.MfaFactorTypeBackupCode:
		codes, err := a.repo.GetBackupCodesForVerification(ctx, userID)
		if err != nil {
			return nil, goerror.NewServer(err)
		}

		var matched *domain.BackupCode
		for _, c := range codes {
			// backup codes stored as argon2 hash; verify via argon2id
			if a.argon2id.Verify(string(c.CodeHash), input.Code) {
				tmp := c
				matched = &tmp
				break
			}

			// also try SHA256 hex comparison fallback
			if string(c.CodeHash) == string(hashSHA256Hex(input.Code)) {
				tmp := c
				matched = &tmp
				break
			}
		}

		if matched == nil {
			return nil, goerror.NewBusiness("invalid backup code", goerror.CodeUnauthorized)
		}

		_ = a.repo.MarkBackupCodeUsed(ctx, matched.ID, toPgTimestamptz(now))

	default:
		return nil, goerror.NewBusiness("unsupported factor type for complete mfa", goerror.CodeInvalidInput)
	}

	// Mark flow completed
	if err := flow.Complete(now); err != nil {
		return nil, goerror.NewBusiness(err.Error(), goerror.CodeInvalidInput)
	}

	_ = a.repo.UpdateAuthFlow(ctx, flow)

	// Issue tokens and create session
	primaryEmail, _ := a.getPrimaryEmail(ctx, userID)
	if primaryEmail == "" {
		primaryEmail = user.Name
	}

	access, refresh, err := a.issueTokens(userID, primaryEmail)
	if err != nil {
		return nil, err
	}

	sessionID := a.uid.Generate()
	tokenHash := hashToken(access)
	expiresAt := now.Add(a.config.GetMinute("modules.identity.jwt.access.ttl"))
	if expiresAt.IsZero() || expiresAt.Before(now) {
		expiresAt = now.Add(15 * time.Minute)
	}

	sess, _ := domain.NewSession(sessionID, userID, tokenHash, now, expiresAt, input.IPAddress, input.UserAgent)
	sess.MarkMFAVerified(now)
	_ = a.repo.CreateSession(ctx, *sess)

	refreshID := a.uid.Generate()
	refreshHash := hashToken(refresh)
	refreshExpires := now.Add(a.config.GetDay("modules.identity.jwt.refresh.ttl"))
	if refreshExpires.IsZero() || refreshExpires.Before(now) {
		refreshExpires = now.Add(7 * 24 * time.Hour)
	}

	rt, _ := domain.NewRefreshToken(refreshID, sessionID, refreshHash, now, refreshExpires, input.IPAddress)
	if rt != nil {
		_ = a.repo.CreateRefreshToken(ctx, *rt)
	}

	a.logSecurityEvent(ctx, &userID, "mfa.success", input.IPAddress, input.UserAgent, map[string]any{"factor_type": factor.Type, "factor_id": factor.ID})
	a.logSecurityEvent(ctx, &userID, "login.success", input.IPAddress, input.UserAgent, map[string]any{"method": "mfa", "flow_id": flowID})

	return &CompleteMfaOutput{
		Token:        access,
		RefreshToken: refresh,
		Session:      *sess,
		User:         user,
	}, nil
}
