package application

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

type LoginInput struct {
	Identifier string    `validate:"required"`
	Password   *string   `validate:"omitempty,password"`
	FlowID     *string   `validate:"omitempty"`
	Meta       MetaInput `validate:"required"`
}

type LoginOutput struct {
	Token               *string
	RefreshToken        *string
	Session             *domain.Session
	User                *domain.User
	Flow                *domain.AuthFlow
	MFARequired         bool
	AvailableMFAMethods []domain.MfaFactorType
	NextStep            string
}

func (a *Application) Login(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "Login")
	defer span.End()

	input.Identifier = strings.TrimSpace(input.Identifier)

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	var user *domain.User
	var primaryEmail string
	var err error

	// Try email first (lowercase, contains @)
	if strings.Contains(input.Identifier, "@") {
		user, primaryEmail, err = a.loginWithEmail(ctx, input)
		if err != nil {
			return nil, err
		}
	} else if rePhone.MatchString(input.Identifier) {
		user, primaryEmail, err = a.loginWithPhone(ctx, input)
		if err != nil {
			return nil, err
		}
	} else {
		slog.WarnContext(ctx, "identifier is not email or phone number")
		return nil, goerror.NewBusiness("invalid identifier format", goerror.CodeInvalidInput)
	}

	if user.IsDeleted() {
		slog.WarnContext(ctx, "user is already deleted")
		return nil, goerror.NewBusiness("account is deleted", goerror.CodeForbidden)
	}

	if !user.CanAuthenticate() {
		slog.WarnContext(ctx, "user status is not active")
		return nil, goerror.NewBusiness("account is not active", goerror.CodeForbidden)
	}

	// If password provided, verify
	if input.Password != nil && *input.Password != "" {
		cred, err := a.repo.GetPasswordCredentialByUserID(ctx, user.ID)
		if err != nil {
			if errors.Is(err, domain.ErrPasswordCredentialNotFound) {
				return nil, goerror.NewBusiness("invalid identifier or password", goerror.CodeUnauthorized)
			}

			return nil, goerror.NewServer(err)
		}

		if !a.argon2id.Verify(cred.Password, *input.Password) {
			a.logSecurityEvent(ctx, &user.ID, "login.failed", &input.Meta.IPAddress, &input.Meta.UserAgent, map[string]any{"reason": "invalid_password", "identifier": input.Identifier})
			return nil, goerror.NewBusiness("invalid identifier or password", goerror.CodeUnauthorized)
		}
	} else {
		// Password not provided - this would be for passkey/magic link initiation; for now require password
		return nil, goerror.NewBusiness("password is required", goerror.CodeInvalidInput)
	}

	// Check MFA factors
	factors, err := a.repo.ListMfaFactorsByUserID(ctx, user.ID, false)
	if err != nil {
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
		flowID := a.uid.Generate()
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

		flow, _ := domain.NewAuthFlow(flowID, &user.ID, domain.AuthFlowTypeLogin, domain.AuthFlowStatePendingMFA, &input.Meta.IPAddress, &input.Meta.UserAgent, map[string]any{"available_methods": available}, now, expires)
		if flow != nil {
			_ = a.repo.CreateAuthFlow(ctx, *flow)
		}

		a.logSecurityEvent(ctx, &user.ID, "login.mfa_required", &input.Meta.IPAddress, &input.Meta.UserAgent, map[string]any{"flow_id": flowID})

		return &LoginOutput{
			Flow:                flow,
			MFARequired:         true,
			AvailableMFAMethods: available,
			NextStep:            "mfa",
			User:                user,
		}, nil
	}

	// No MFA, issue tokens and create session
	now := a.clock.Now()
	access, refresh, err := a.issueTokens(user.ID, primaryEmail)
	if err != nil {
		return nil, err
	}

	sessionID := a.uid.Generate()
	tokenHash := hashToken(access)
	expiresAt := now.Add(a.config.GetMinute("modules.identity.jwt.access.ttl"))
	if expiresAt.IsZero() || expiresAt.Before(now) {
		expiresAt = now.Add(15 * time.Minute)
	}

	sess, err := domain.NewSession(sessionID, user.ID, tokenHash, now, expiresAt, &input.Meta.IPAddress, &input.Meta.UserAgent)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	if err := a.repo.CreateSession(ctx, *sess); err != nil {
		return nil, goerror.NewServer(err)
	}

	refreshID := a.uid.Generate()
	refreshHash := hashToken(refresh)
	refreshExpires := now.Add(a.config.GetDay("modules.identity.jwt.refresh.ttl"))
	if refreshExpires.IsZero() || refreshExpires.Before(now) {
		refreshExpires = now.Add(7 * 24 * time.Hour)
	}

	rt, _ := domain.NewRefreshToken(refreshID, sessionID, refreshHash, now, refreshExpires, &input.Meta.IPAddress)
	if rt != nil {
		_ = a.repo.CreateRefreshToken(ctx, *rt)
	}

	a.logSecurityEvent(ctx, &user.ID, "login.success", &input.Meta.IPAddress, &input.Meta.UserAgent, map[string]any{"method": "password"})

	// Touch session? already created
	_ = jwt.GetAuth

	return &LoginOutput{
		Token:        &access,
		RefreshToken: &refresh,
		Session:      sess,
		User:         user,
		NextStep:     "completed",
	}, nil
}

func (a *Application) loginWithEmail(ctx context.Context, input LoginInput) (*domain.User, string, error) {
	emailRec, err := a.repo.GetUserEmailByEmail(ctx, strings.ToLower(input.Identifier))
	if errors.Is(err, domain.ErrEmailNotFound) {
		slog.WarnContext(ctx, "user emails not found")
		return nil, "", goerror.NewBusiness("invalid identifier or password", goerror.CodeUnauthorized)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user emails by email", "error", err)
		return nil, "", goerror.NewServer(err)
	}

	u, err := a.repo.GetUserByID(ctx, emailRec.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "error", err)
		return nil, "", goerror.NewServer(err)
	}

	// If primary not same, get primary for token
	primaryEmail := emailRec.Email
	if pe, err := a.repo.GetPrimaryUserEmailByUserID(ctx, u.ID); err == nil {
		primaryEmail = pe.Email
	}

	return &u, primaryEmail, nil
}

func (a *Application) loginWithPhone(ctx context.Context, input LoginInput) (*domain.User, string, error) {
	ph, err := a.repo.GetUserPhoneByPhone(ctx, input.Identifier)
	if errors.Is(err, domain.ErrPhoneNotFound) {
		slog.WarnContext(ctx, "user phone not found")
		return nil, "", goerror.NewBusiness("invalid identifier or password", goerror.CodeUnauthorized)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user phone by phone number", "error", err)
		return nil, "", goerror.NewServer(err)
	}

	u, err := a.repo.GetUserByID(ctx, ph.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "error", err)
		return nil, "", goerror.NewServer(err)
	}

	primaryEmail := input.Identifier
	if pe, err := a.repo.GetPrimaryUserEmailByUserID(ctx, u.ID); err == nil {
		primaryEmail = pe.Email
	}

	return &u, primaryEmail, nil
}
