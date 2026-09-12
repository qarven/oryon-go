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

type LoginInput struct {
	Identifier string    `validate:"required"`
	Password   string    `validate:"password"`
	Meta       MetaInput `validate:"required"`
}

type LoginOutput struct {
	Token               *string
	TokenExpiresIn      *int64
	RefreshToken        *string
	Session             *domain.Session
	User                *domain.User
	Flow                *domain.AuthFlow
	MFARequired         bool
	AvailableMFAMethods []domain.MfaFactorType
}

type CreateLoginSessionData struct {
	Session      domain.Session
	RefreshToken domain.RefreshToken
}

func (a *Application) Login(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "Login")
	defer span.End()

	input.Identifier = strings.TrimSpace(input.Identifier)

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	var user *domain.User
	var err error

	if strings.Contains(input.Identifier, "@") {
		user, err = a.loginWithEmail(ctx, input)
		if err != nil {
			return nil, err
		}
	} else if rePhone.MatchString(input.Identifier) {
		user, err = a.loginWithPhone(ctx, input)
		if err != nil {
			return nil, err
		}
	} else if reUsername.MatchString(input.Identifier) {
		user, err = a.loginWithUsername(ctx, input)
		if err != nil {
			return nil, err
		}
	} else {
		slog.WarnContext(ctx, "identifier is not email, phone number or username")
		return nil, goerror.NewBusiness("invalid identifier or password", goerror.CodeUnauthorized)
	}

	if user.IsDeleted() {
		slog.WarnContext(ctx, "user is already deleted")
		return nil, goerror.NewBusiness("account is deleted", goerror.CodeForbidden)
	}

	if !user.CanAuthenticate() {
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
			&cred.UserID,
			domain.SecurityEventTypeLoginFailed,
			input.Meta,
			map[string]any{"reason": "invalid_password", "identifier": input.Identifier},
		)
		slog.WarnContext(ctx, "password credential is not match")
		return nil, goerror.NewBusiness("invalid identifier or password", goerror.CodeUnauthorized)
	}

	// Check MFA factors
	factors, err := a.repo.ListMfaFactorsByUserID(ctx, user.ID, false)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get mfa factor by user_id", "error", err)
		return nil, goerror.NewServer(err)
	}

	var activeFactors []domain.MfaFactor
	for _, f := range factors {
		if f.IsVerified() && f.IsActive() {
			activeFactors = append(activeFactors, f)
		}
	}

	if len(activeFactors) > 0 {
		now := a.clock.Now()
		expires := now.Add(10 * time.Minute)

		// Determine available methods
		available := make([]domain.MfaFactorType, 0, len(activeFactors))
		typMap := map[domain.MfaFactorType]bool{}

		for _, f := range activeFactors {
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
			IPAddress: &input.Meta.IPAddress,
			UserAgent: &input.Meta.UserAgent,
			Context:   map[string]any{"available_methods": available},
			CreatedAt: now,
			ExpiresAt: expires,
		}
		if err := a.repo.CreateAuthFlow(ctx, flow); err != nil {
			slog.ErrorContext(ctx, "failed to create auth flow", "error", err)
			return nil, goerror.NewServer(err)
		}

		a.logSecurityEvent(
			&user.ID,
			domain.SecurityEventTypeLoginMFARequired,
			input.Meta,
			map[string]any{"flow_id": flow.ID},
		)

		return &LoginOutput{
			Flow:                &flow,
			MFARequired:         true,
			AvailableMFAMethods: available,
			User:                user,
		}, nil
	}

	// No MFA, issue tokens and create session
	access, refresh, err := a.issueTokens(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	now := a.clock.Now()
	tokenHash, err := a.sha256.Hash(access)
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
		ID:         a.uid.Generate(),
		UserID:     user.ID,
		TokenHash:  tokenHash,
		CreatedAt:  now,
		ExpiresAt:  now.Add(a.config.GetDay("modules.identity.session.ttl")),
		IPAddress:  &input.Meta.IPAddress,
		UserAgent:  &input.Meta.UserAgent,
		LastSeenAt: &now,
	}

	if err := a.repo.CreateLoginSession(ctx, CreateLoginSessionData{
		Session: session,
		RefreshToken: domain.RefreshToken{
			ID:        a.uid.Generate(),
			SessionID: session.ID,
			TokenHash: refreshHash,
			IssuedAt:  now,
			ExpiresAt: now.Add(a.config.GetDay("modules.identity.jwt.refresh.ttl")),
			CreatedIP: &input.Meta.IPAddress,
		},
	}); err != nil {
		slog.ErrorContext(ctx, "failed to create login session", "error", err)
		return nil, goerror.NewServer(err)
	}

	a.logSecurityEvent(
		&user.ID,
		domain.SecurityEventTypeLoginSuccess,
		input.Meta,
		map[string]any{"method": "password"},
	)

	tokenExpiresIn := int64(a.config.GetMinute("modules.identity.jwt.access.ttl").Seconds())

	return &LoginOutput{
		Token:          &access,
		TokenExpiresIn: &tokenExpiresIn,
		RefreshToken:   &refresh,
		Session:        &session,
		User:           user,
	}, nil
}

func (a *Application) loginWithEmail(ctx context.Context, input LoginInput) (*domain.User, error) {
	emailRec, err := a.repo.GetUserEmailByEmail(ctx, strings.ToLower(input.Identifier))
	if errors.Is(err, domain.ErrEmailNotFound) {
		slog.WarnContext(ctx, "user emails not found")
		return nil, goerror.NewBusiness("invalid identifier or password", goerror.CodeUnauthorized)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user emails by email", "error", err)
		return nil, goerror.NewServer(err)
	}

	u, err := a.repo.GetUserByID(ctx, emailRec.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "error", err)
		return nil, goerror.NewServer(err)
	}

	return u, nil
}

func (a *Application) loginWithUsername(ctx context.Context, input LoginInput) (*domain.User, error) {
	u, err := a.repo.GetUserByUsername(ctx, input.Identifier)
	if errors.Is(err, domain.ErrUserNotFound) {
		slog.WarnContext(ctx, "user not found by username")
		return nil, goerror.NewBusiness("invalid identifier or password", goerror.CodeUnauthorized)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by username", "error", err)
		return nil, goerror.NewServer(err)
	}

	return u, nil
}

func (a *Application) loginWithPhone(ctx context.Context, input LoginInput) (*domain.User, error) {
	ph, err := a.repo.GetUserPhoneByPhone(ctx, input.Identifier)
	if errors.Is(err, domain.ErrPhoneNotFound) {
		slog.WarnContext(ctx, "user phone not found")
		return nil, goerror.NewBusiness("invalid identifier or password", goerror.CodeUnauthorized)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user phone by phone number", "error", err)
		return nil, goerror.NewServer(err)
	}

	u, err := a.repo.GetUserByID(ctx, ph.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "error", err)
		return nil, goerror.NewServer(err)
	}

	return u, nil
}
