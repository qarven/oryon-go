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

type CreateLoginSessionData struct {
	Session      domain.Session
	RefreshToken domain.RefreshToken
}

// ensureUserCanAuthenticate rejects deleted or inactive users.
func ensureUserCanAuthenticate(ctx context.Context, user *domain.User) error {
	if user.IsDeleted() {
		slog.WarnContext(ctx, "user is already deleted")

		return goerror.NewBusiness("account is deleted", goerror.CodeForbidden)
	}

	if !user.CanAuthenticate() {
		slog.WarnContext(ctx, "user status is not active")

		return goerror.NewBusiness("account is not active", goerror.CodeForbidden)
	}

	return nil
}

type passwordLoginSessionData struct {
	User        *domain.User
	Meta        MetaInput
	Session     domain.Session
	Access      string
	Refresh     string
	RefreshHash []byte
	Now         time.Time
}

// storePasswordLoginSession persists the login session and completes the
// password login output.
func (a *Application) storePasswordLoginSession(
	ctx context.Context,
	data passwordLoginSessionData,
) (*LoginOutput, error) {
	err := a.repo.CreateLoginSession(ctx, CreateLoginSessionData{
		Session: data.Session,
		RefreshToken: domain.RefreshToken{
			ID:        a.uid.Generate(),
			SessionID: data.Session.ID,
			TokenHash: data.RefreshHash,
			IssuedAt:  data.Now,
			ExpiresAt: data.Now.Add(a.config.GetDay("modules.identity.jwt.refresh.ttl")),
			CreatedIP: &data.Meta.IPAddress,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to create login session", "error", err)

		return nil, goerror.NewServer(err)
	}

	a.logSecurityEvent(
		ctx,
		&data.User.ID,
		domain.SecurityEventTypeLoginSuccess,
		data.Meta,
		map[string]any{"method": "password"},
	)

	tokenExpiresIn := int64(a.config.GetMinute("modules.identity.jwt.access.ttl").Seconds())

	return &LoginOutput{Token: &LoginToken{
		AccessToken:  data.Access,
		ExpiresIn:    tokenExpiresIn,
		RefreshToken: data.Refresh,
		Session:      data.Session,
		User:         *data.User,
	}}, nil
}

func (a *Application) loginWithEmail(ctx context.Context, identifier string) (*domain.User, error) {
	emailRec, err := a.repo.GetUserEmailByEmail(ctx, strings.ToLower(identifier))
	if errors.Is(err, domain.ErrEmailNotFound) {
		slog.WarnContext(ctx, "user emails not found")

		return nil, goerror.NewBusiness("invalid identifier or password", goerror.CodeUnauthorized)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user emails by email", "error", err)

		return nil, goerror.NewServer(err)
	}

	user, err := a.repo.GetUserByID(ctx, emailRec.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "error", err)

		return nil, goerror.NewServer(err)
	}

	return user, nil
}

func (a *Application) loginWithUsername(ctx context.Context, identifier string) (*domain.User, error) {
	user, err := a.repo.GetUserByUsername(ctx, identifier)
	if errors.Is(err, domain.ErrUserNotFound) {
		slog.WarnContext(ctx, "user not found by username")

		return nil, goerror.NewBusiness("invalid identifier or password", goerror.CodeUnauthorized)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by username", "error", err)

		return nil, goerror.NewServer(err)
	}

	return user, nil
}

func (a *Application) loginWithPhone(ctx context.Context, identifier string) (*domain.User, error) {
	phoneRec, err := a.repo.GetUserPhoneByPhone(ctx, identifier)
	if errors.Is(err, domain.ErrPhoneNotFound) {
		slog.WarnContext(ctx, "user phone not found")

		return nil, goerror.NewBusiness("invalid identifier or password", goerror.CodeUnauthorized)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user phone by phone number", "error", err)

		return nil, goerror.NewServer(err)
	}

	user, err := a.repo.GetUserByID(ctx, phoneRec.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "error", err)

		return nil, goerror.NewServer(err)
	}

	return user, nil
}

// ===== Login: complete MFA =====

type CompleteLoginMfaInput struct {
	FlowID     int64                `validate:"required"`
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

	validateErr := a.validator.Validate(input)
	if validateErr != nil {
		return nil, goerror.NewInvalidInput(validateErr)
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

	out, err := a.finishMfaLogin(ctx, mfaLoginFinishData{
		Flow:       flow,
		User:       user,
		Factor:     factor,
		BackupCode: backupCode,
		Meta:       input.Meta,
		Now:        now,
	})
	if err != nil {
		return nil, err
	}

	a.logSecurityEvent(
		ctx,
		&user.ID,
		domain.SecurityEventTypeLoginSuccess,
		input.Meta,
		map[string]any{
			"method":               "mfa",
			securityEventFlowIDKey: flow.ID,
			"factor_type":          factor.Type,
			"factor_id":            factor.ID,
		},
	)

	return out, nil
}

// loadMfaLoginFlow loads the MFA login flow and its user, ensuring the flow
// exists, is unexpired, is pending MFA, and is bound to a user.
func (a *Application) loadMfaLoginFlow(
	ctx context.Context,
	flowID int64,
) (*domain.AuthFlow, *domain.User, time.Time, error) {
	flow, err := a.repo.GetAuthFlowByID(ctx, flowID)
	if errors.Is(err, domain.ErrAuthFlowNotFound) {
		return nil, nil, time.Time{}, goerror.NewBusiness("flow not found", goerror.CodeUnauthorized)
	}

	if err != nil {
		return nil, nil, time.Time{}, goerror.NewServer(err)
	}

	now := a.clock.Now()
	if flow.IsExpired(now) {
		return nil, nil, time.Time{}, goerror.NewBusiness("flow expired", goerror.CodeUnauthorized)
	}

	if flow.FlowState != domain.AuthFlowStatePendingMFA {
		return nil, nil, time.Time{}, goerror.NewBusiness("flow not pending mfa", goerror.CodeUnauthorized)
	}

	if flow.UserID == nil {
		return nil, nil, time.Time{}, goerror.NewBusiness("flow has no user", goerror.CodeUnauthorized)
	}

	user, err := a.repo.GetUserByID(ctx, *flow.UserID)
	if errors.Is(err, domain.ErrUserNotFound) {
		// data integrity violation
		return nil, nil, time.Time{}, goerror.NewBusiness("user not found", goerror.CodeUnauthorized)
	}

	if err != nil {
		return nil, nil, time.Time{}, goerror.NewServer(err)
	}

	return flow, user, now, nil
}

// findLoginMfaFactor returns the verified, active factor of the requested
// type for the user.
func (a *Application) findLoginMfaFactor(
	ctx context.Context,
	userID int64,
	factorType domain.MfaFactorType,
) (*domain.MfaFactor, error) {
	factors, err := a.repo.ListMfaFactorsByUserID(ctx, userID, false)
	if err != nil {
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
		return nil, goerror.NewBusiness("no active factor of requested type", goerror.CodeUnauthorized)
	}

	if factor.IsRevoked() {
		return nil, goerror.NewBusiness("factor is revoked", goerror.CodeForbidden)
	}

	if !factor.IsVerified() {
		return nil, goerror.NewBusiness("factor not verified", goerror.CodeForbidden)
	}

	return factor, nil
}

// verifyLoginMfaCode validates the supplied code against the factor, marking
// usage on the factor itself, and returns the consumed backup code, if any.
func (a *Application) verifyLoginMfaCode(
	ctx context.Context,
	factor *domain.MfaFactor,
	userID int64,
	code string,
	now time.Time,
) (*domain.BackupCode, error) {
	switch factor.Type {
	case domain.MfaFactorTypeTOTP:
		return nil, a.verifyLoginTotpCode(ctx, factor, userID, code, now)
	case domain.MfaFactorTypeBackupCode:
		return a.verifyLoginBackupCode(ctx, userID, code, now)
	default:
		return nil, goerror.NewBusiness("unsupported factor type", goerror.CodeInvalidInput)
	}
}

// verifyLoginTotpCode validates a TOTP code and records the factor usage.
func (a *Application) verifyLoginTotpCode(
	ctx context.Context,
	factor *domain.MfaFactor,
	userID int64,
	code string,
	now time.Time,
) error {
	totp, err := a.repo.GetTotpFactorByFactorID(ctx, factor.ID)
	if errors.Is(err, domain.ErrUserNotFound) {
		// data integrity violation
		return goerror.NewBusiness("user not found", goerror.CodeUnauthorized)
	}

	if err != nil {
		return goerror.NewServer(err)
	}

	secret, err := a.mfaEncryption.Decrypt(totp.Secret)
	if err != nil {
		return goerror.NewServer(err)
	}

	if !a.otp.Validate(code, string(secret), now) {
		slog.WarnContext(ctx, "invalid totp code", "user_id", userID, "mfa_id", factor.ID)

		return goerror.NewBusiness("invalid otp code", goerror.CodeUnauthorized)
	}

	factor.LastUsedAt = &now

	return nil
}

// verifyLoginBackupCode validates a backup code and returns it marked as used.
// Codes are single-use in canonical XXXXXXXX-XXXXXXXX format; used codes
// are skipped so they cannot be replayed.
func (a *Application) verifyLoginBackupCode(
	ctx context.Context,
	userID int64,
	code string,
	now time.Time,
) (*domain.BackupCode, error) {
	if !domain.IsValidBackupCodeFormat(code) {
		slog.WarnContext(ctx, "invalid backup code format", "user_id", userID)

		return nil, goerror.NewBusiness("invalid backup code", goerror.CodeUnauthorized)
	}

	codes, err := a.repo.ListBackupCodesByUserID(ctx, userID)
	if err != nil {
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

	return nil, goerror.NewBusiness("invalid backup code", goerror.CodeUnauthorized)
}

type mfaLoginFinishData struct {
	Flow       *domain.AuthFlow
	User       *domain.User
	Factor     *domain.MfaFactor
	BackupCode *domain.BackupCode
	Meta       MetaInput
	Now        time.Time
}

// finishMfaLogin issues tokens, persists the login session, and completes
// the MFA flow.
func (a *Application) finishMfaLogin(
	ctx context.Context,
	data mfaLoginFinishData,
) (*CompleteLoginMfaOutput, error) {
	issue, err := a.issueTokens(ctx, data.User.ID)
	if err != nil {
		return nil, err
	}

	accessHash, err := a.sha256.Hash(issue.accessToken)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash access token", "error", err)

		return nil, goerror.NewServer(err)
	}

	refreshHash, err := a.sha256.Hash(issue.refreshToken)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash refresh token", "error", err)

		return nil, goerror.NewServer(err)
	}

	session := domain.Session{
		ID:            a.uid.Generate(),
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
		Token:          issue.accessToken,
		TokenExpiresIn: tokenExpiresIn,
		RefreshToken:   issue.refreshToken,
		User:           *data.User,
	}, nil
}

// persistMfaLogin completes the MFA flow and stores the login session with
// its refresh token.
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
			ID:        a.uid.Generate(),
			SessionID: session.ID,
			TokenHash: refreshHash,
			IssuedAt:  data.Now,
			ExpiresAt: data.Now.Add(a.config.GetDay("modules.identity.jwt.refresh.ttl")),
			CreatedIP: &data.Meta.IPAddress,
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to complete mfa login", "error", err)

		return goerror.NewServer(err)
	}

	return nil
}
