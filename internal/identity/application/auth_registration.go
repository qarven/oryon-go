package application

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

const (
	registrationRequestEmailKeyPrefix = "registration:req:email:"
	registrationRequestPhoneKeyPrefix = "registration:req:phone:"
	registrationRequestIPKeyPrefix    = "registration:req:ip:"
)

// Flow context keys for a pending registration. The password is stored as an
// argon2id hash, never plaintext.
const (
	regCtxName         = "name"
	regCtxEmail        = "email"
	regCtxPhone        = "phone"
	regCtxPasswordHash = "password_hash"
)

type RegistrationInput struct {
	Email    *string   `validate:"omitempty,email"`
	Phone    *string   `validate:"omitempty,e164"`
	Password string    `validate:"required,password"`
	Name     string    `validate:"required,min=3"`
	Meta     MetaInput `validate:"required"`
}

type RegistrationOutput struct {
	Flow domain.AuthFlow
	// Challenge is the primary OTP challenge (email if given, else phone).
	// Clients discover it via RequestEmailVerification; VerifyEmail needs its ID.
	Challenge *domain.VerificationChallenge
}

// CompleteRegistrationData materializes a verified registration in one transaction.
type CompleteRegistrationData struct {
	User      domain.User
	UserEmail *domain.UserEmail
	UserPhone *domain.UserPhoneNumber
	PassCred  domain.PasswordCredential
	Flow      domain.AuthFlow
	Challenge domain.VerificationChallenge
}

type EventRegistrationData struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Registration starts a verify-before-create flow. No user, email, or phone row
// is created here, so an unverified identifier can never squat the unique slot.
// Ownership is proven later via VerifyEmail, which creates the user.
func (a *Application) Registration(ctx context.Context, input RegistrationInput) (*RegistrationOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "Registration")
	defer span.End()

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	var email, phone string
	if input.Email != nil {
		email = strings.ToLower(strings.TrimSpace(*input.Email))
	}

	if input.Phone != nil {
		if !rePhone.MatchString(*input.Phone) {
			return nil, goerror.NewInvalidInput(nil, "phone", "phone must be E.164 format")
		}

		phone = strings.TrimSpace(*input.Phone)
	}

	if email == "" && phone == "" {
		return nil, goerror.NewInvalidInput(nil, "email", "one of email or phone is required")
	}

	// Rate-limit before any lookup so enumeration probes are throttled too.
	rateLimitMax := a.config.GetInt("modules.identity.verification.rate_limit_max")
	rateWindow := a.config.GetMinute("modules.identity.verification.rate_limit_window")

	keys := []string{}
	if email != "" {
		keys = append(keys, registrationRequestEmailKeyPrefix+email)
	}

	if phone != "" {
		keys = append(keys, registrationRequestPhoneKeyPrefix+phone)
	}

	if strings.TrimSpace(input.Meta.IPAddress) != "" {
		keys = append(keys, registrationRequestIPKeyPrefix+input.Meta.IPAddress)
	}

	for _, key := range keys {
		count, err := a.cache.IncrementVerificationRequest(ctx, key, rateWindow)
		if err != nil {
			slog.ErrorContext(ctx, "failed to increment registration rate limit", "error", err)
			return nil, goerror.NewServer(err)
		}

		if count > int64(rateLimitMax) {
			slog.WarnContext(ctx, "registration rate limit exceeded")
			return nil, goerror.NewBusiness("too many requests", goerror.CodeTooManyRequest)
		}
	}

	// Only identifiers owned by real accounts conflict. Pending (unverified)
	// registrations live in auth_flows/verification_challenges, never here.
	if email != "" {
		if _, err := a.repo.GetUserEmailByEmail(ctx, email); err == nil {
			slog.WarnContext(ctx, "email already exists")
			return nil, goerror.NewBusiness("email already registered", goerror.CodeConflict)
		} else if !errors.Is(err, domain.ErrEmailNotFound) {
			slog.ErrorContext(ctx, "failed to get user email by email", "error", err)
			return nil, goerror.NewServer(err)
		}
	}

	if phone != "" {
		if _, err := a.repo.GetUserPhoneByPhone(ctx, phone); err == nil {
			slog.WarnContext(ctx, "phone already exists")
			return nil, goerror.NewBusiness("phone already registered", goerror.CodeConflict)
		} else if !errors.Is(err, domain.ErrPhoneNotFound) {
			slog.ErrorContext(ctx, "failed to get user phone by phone number", "error", err)
			return nil, goerror.NewServer(err)
		}
	}

	hash, err := a.argon2id.Hash(input.Password)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash password", "error", err)
		return nil, goerror.NewServer(err)
	}

	now := a.clock.Now()
	flowID := a.uid.Generate()

	flowCtx := map[string]any{
		regCtxName:         strings.TrimSpace(input.Name),
		regCtxPasswordHash: string(hash),
	}
	if email != "" {
		flowCtx[regCtxEmail] = email
	}

	if phone != "" {
		flowCtx[regCtxPhone] = phone
	}

	flow := domain.AuthFlow{
		ID:        flowID,
		UserID:    nil,
		FlowType:  domain.AuthFlowTypeRegistration,
		FlowState: domain.AuthFlowStatePendingVerification,
		IPAddress: &input.Meta.IPAddress,
		UserAgent: &input.Meta.UserAgent,
		Context:   flowCtx,
		ExpiresAt: now.Add(a.config.GetMinute("modules.identity.auth_flow.ttl")),
		CreatedAt: now,
	}

	maxAttempts := int16(a.config.GetInt("modules.identity.verification.max_attempts"))
	challengeTTL := a.config.GetMinute("modules.identity.verification.ttl")

	var challenges []domain.VerificationChallenge

	newChallenge := func(identifier string, purpose domain.VerificationPurpose) (*domain.VerificationChallenge, error) {
		rawCode, err := generateEmailVerificationCode()
		if err != nil {
			return nil, err
		}

		codeHash, err := a.sha256.Hash(rawCode)
		if err != nil {
			return nil, err
		}

		ch := domain.VerificationChallenge{
			ID:          a.uid.Generate(),
			UserID:      nil,
			FlowID:      &flowID,
			Identifier:  identifier,
			Purpose:     purpose,
			CodeHash:    codeHash,
			Attempts:    0,
			MaxAttempts: maxAttempts,
			IPAddress:   &input.Meta.IPAddress,
			ExpiresAt:   now.Add(challengeTTL),
			CreatedAt:   now,
		}

		a.sendEmailVerificationMock(ch, rawCode)

		return &ch, nil
	}

	if email != "" {
		ch, err := newChallenge(email, domain.VerificationPurposeEmailVerification)
		if err != nil {
			slog.ErrorContext(ctx, "failed to create email verification code", "error", err)
			return nil, goerror.NewServer(err)
		}

		challenges = append(challenges, *ch)
	}

	if phone != "" {
		ch, err := newChallenge(phone, domain.VerificationPurposePhoneVerification)
		if err != nil {
			slog.ErrorContext(ctx, "failed to create phone verification code", "error", err)
			return nil, goerror.NewServer(err)
		}

		challenges = append(challenges, *ch)
	}

	if err := a.repo.CreateRegistrationFlow(ctx, flow, challenges); err != nil {
		slog.ErrorContext(ctx, "failed to create registration flow", "error", err)
		return nil, goerror.NewServer(err)
	}

	a.logSecurityEvent(
		nil,
		domain.SecurityEventTypeRegistrationRequested,
		input.Meta,
		map[string]any{"flow_id": flow.ID, "email": email, "phone": phone},
	)

	out := &RegistrationOutput{Flow: flow}
	if len(challenges) > 0 {
		out.Challenge = &challenges[0]
	}

	return out, nil
}
