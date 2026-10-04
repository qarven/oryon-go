package application

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type LoginInput struct {
	Identifier string    `validate:"required"`
	Password   string    `validate:"password"`
	Meta       MetaInput `validate:"required"`
}

type LoginToken struct {
	AccessToken  string
	ExpiresIn    int64
	RefreshToken string
	Session      domain.Session
	User         domain.User
}

type LoginMFA struct {
	Flow                domain.AuthFlow
	AvailableMFAMethods []domain.MfaFactorType
}

type LoginOutput struct {
	Token *LoginToken
	MFA   *LoginMFA
}

func (a *Application) Login(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "Login")
	defer span.End()

	input.Identifier = strings.TrimSpace(input.Identifier)

	err := a.validator.Validate(input)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	user, err := a.resolveLoginUser(ctx, input.Identifier)
	if err != nil {
		return nil, err
	}

	if !user.IsActive() {
		slog.WarnContext(ctx, "user status is not active")

		return nil, goerror.NewBusiness("account is not active", goerror.CodeForbidden)
	}

	cred, err := a.repo.GetPasswordCredentialByUserID(ctx, user.ID)
	if errors.Is(err, domain.ErrPasswordCredentialNotFound) {
		slog.ErrorContext(ctx, "data integrity violation: user has no password credential", "user_id", user.ID)

		return nil, goerror.NewServer(err)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get password credential by user_id", "error", err)

		return nil, goerror.NewServer(err)
	}

	if !a.argon2id.Verify(cred.Password, input.Password) {
		a.logSecurityEvent(
			ctx,
			&cred.UserID,
			domain.SecurityEventTypeLoginFailed,
			input.Meta,
			map[string]any{"reason": "invalid_password", securityEventIdentifierKey: input.Identifier},
		)
		slog.WarnContext(ctx, "password credential is not match")

		return nil, goerror.NewBusiness("invalid identifier or password", goerror.CodeUnauthorized)
	}

	factors, err := a.repo.ListMfaFactorsByUserID(ctx, user.ID, false)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get mfa factor by user_id", "error", err)

		return nil, goerror.NewServer(err)
	}

	if activeFactors := a.activeMfaFactors(factors); len(activeFactors) > 0 {
		return a.startMfaLogin(ctx, user, activeFactors, input.Meta)
	}

	return a.finishPasswordLogin(ctx, user, input.Meta)
}

func (a *Application) resolveLoginUser(
	ctx context.Context,
	identifier string,
) (*domain.User, error) {
	switch {
	case strings.Contains(identifier, "@"):
		return a.loginWithEmail(ctx, identifier)
	case rePhone.MatchString(identifier):
		return a.loginWithPhone(ctx, identifier)
	case reUsername.MatchString(identifier):
		return a.loginWithUsername(ctx, identifier)
	default:
		slog.WarnContext(ctx, "identifier is not email, phone number or username")

		return nil, goerror.NewBusiness("invalid identifier or password", goerror.CodeUnauthorized)
	}
}

func (a *Application) activeMfaFactors(factors []domain.MfaFactor) []domain.MfaFactor {
	var active []domain.MfaFactor

	for _, f := range factors {
		if f.IsVerified() && f.IsActive() {
			active = append(active, f)
		}
	}

	return active
}

func (a *Application) startMfaLogin(
	ctx context.Context,
	user *domain.User,
	factors []domain.MfaFactor,
	meta MetaInput,
) (*LoginOutput, error) {
	now := a.clock.Now()

	// Determine available methods
	available := make([]domain.MfaFactorType, 0, len(factors))
	typMap := map[domain.MfaFactorType]bool{}

	for _, f := range factors {
		if !typMap[f.Type] {
			available = append(available, f.Type)
			typMap[f.Type] = true
		}
	}

	flow := domain.AuthFlow{
		ID:        a.uid.Generate(),
		UserID:    &user.ID,
		FlowType:  domain.AuthFlowTypeLogin,
		FlowState: domain.AuthFlowStatePendingMFA,
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
		Context:   map[string]any{"available_methods": available},
		CreatedAt: now,
		ExpiresAt: now.Add(a.config.GetMinute("modules.identity.flow.ttl")),
	}

	err := a.repo.CreateAuthFlow(ctx, flow)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create auth flow", "error", err)

		return nil, goerror.NewServer(err)
	}

	a.logSecurityEvent(
		ctx,
		&user.ID,
		domain.SecurityEventTypeLoginMFARequired,
		meta,
		map[string]any{securityEventFlowIDKey: flow.ID},
	)

	return &LoginOutput{MFA: &LoginMFA{
		Flow:                flow,
		AvailableMFAMethods: available,
	}}, nil
}

func (a *Application) finishPasswordLogin(
	ctx context.Context,
	user *domain.User,
	meta MetaInput,
) (*LoginOutput, error) {
	issue, err := a.issueTokens(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	now := a.clock.Now()

	tokenHash, err := a.sha256.Hash(issue.accessToken)
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
		ID:         a.uid.Generate(),
		UserID:     user.ID,
		TokenHash:  tokenHash,
		CreatedAt:  now,
		ExpiresAt:  now.Add(a.config.GetDay("modules.identity.session.ttl")),
		IPAddress:  &meta.IPAddress,
		UserAgent:  &meta.UserAgent,
		LastSeenAt: &now,
	}

	return a.storePasswordLoginSession(ctx, passwordLoginSessionData{
		User:        user,
		Meta:        meta,
		Session:     session,
		Access:      issue.accessToken,
		Refresh:     issue.refreshToken,
		RefreshHash: refreshHash,
		Now:         now,
	})
}
