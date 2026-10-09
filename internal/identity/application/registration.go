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
}

type EventRegistrationData struct {
	Name     string `json:"name"`
	Code     string `json:"code"`
	Identity string `json:"identity"`
	Channel  string `json:"channel"` // email, phone
}

type registrationChallengeData struct {
	flowID      domain.ID
	name        string
	ipAddress   string
	now         time.Time
	maxAttempts int16
	ttl         time.Duration
}

func (a *Application) Registration(ctx context.Context, input RegistrationInput) (*RegistrationOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "Registration")
	defer span.End()

	err := a.validator.Validate(input)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	var email, phone string
	if input.Email != nil {
		email = strings.ToLower(strings.TrimSpace(*input.Email))
	}

	if input.Phone != nil {
		phone = strings.TrimSpace(*input.Phone)
	}

	err = a.checkVerificationRateLimit(ctx, email, phone, strings.TrimSpace(input.Meta.IPAddress))
	if err != nil {
		return nil, err
	}

	err = a.ensureRegistrationContactsFree(ctx, email, phone)
	if err != nil {
		return nil, err
	}

	hash, err := a.argon2id.Hash(input.Password)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash password", "error", err)

		return nil, goerror.NewServer(err)
	}

	now := a.clock.Now()
	flow := domain.AuthFlow{
		ID:        domain.IDFrom(a.uuid.Generate()),
		UserID:    nil,
		FlowType:  domain.AuthFlowTypeRegistration,
		FlowState: domain.AuthFlowStatePendingVerification,
		IPAddress: &input.Meta.IPAddress,
		UserAgent: &input.Meta.UserAgent,
		Context: map[string]any{
			regCtxName:         strings.TrimSpace(input.Name),
			regCtxPasswordHash: string(hash),
			regCtxEmail:        email,
			regCtxPhone:        phone,
		},
		ExpiresAt: now.Add(a.config.GetMinute("modules.identity.flow.ttl")),
		CreatedAt: now,
	}

	challenges, err := a.issueRegistrationChallenges(ctx, registrationChallengeData{
		flowID:      flow.ID,
		name:        strings.TrimSpace(input.Name),
		ipAddress:   input.Meta.IPAddress,
		now:         now,
		maxAttempts: int16(a.config.GetInt("modules.identity.verification.max_attempts")),
		ttl:         a.config.GetMinute("modules.identity.verification.ttl"),
	}, email, phone)
	if err != nil {
		return nil, err
	}

	err = a.repo.CreateRegistrationFlow(ctx, flow, challenges)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create registration flow", "error", err)

		return nil, goerror.NewServer(err)
	}

	a.securityEvent(domain.SecurityEventTypeRegistrationRequested).
		WithMeta(input.Meta).
		With("flow_id", flow.ID).
		With("email", email).
		With("phone", phone).
		Emit(ctx)

	return &RegistrationOutput{Flow: flow}, nil
}

func (a *Application) ensureRegistrationContactsFree(
	ctx context.Context,
	email, phone string,
) error {
	if email != "" {
		_, err := a.repo.GetUserEmailByEmail(ctx, email)
		if err == nil {
			slog.WarnContext(ctx, "email already exists")

			return goerror.NewBusiness("email already registered", goerror.CodeConflict)
		}

		if !errors.Is(err, domain.ErrEmailNotFound) {
			slog.ErrorContext(ctx, "failed to get user email by email", "error", err)

			return goerror.NewServer(err)
		}
	}

	if phone != "" {
		_, err := a.repo.GetUserPhoneByPhone(ctx, phone)
		if err == nil {
			slog.WarnContext(ctx, "phone already exists")

			return goerror.NewBusiness("phone already registered", goerror.CodeConflict)
		}

		if !errors.Is(err, domain.ErrPhoneNotFound) {
			slog.ErrorContext(ctx, "failed to get user phone by phone number", "error", err)

			return goerror.NewServer(err)
		}
	}

	return nil
}

func (a *Application) issueRegistrationChallenge(
	ctx context.Context,
	data registrationChallengeData,
	identifier, channel string,
	purpose domain.VerificationPurpose,
) (*domain.VerificationChallenge, error) {
	rawCode, err := generate6DigitCode()
	if err != nil {
		return nil, err
	}

	codeHash, err := a.sha256.Hash(rawCode)
	if err != nil {
		return nil, err
	}

	challenge := domain.VerificationChallenge{
		ID:          domain.IDFrom(a.uuid.Generate()),
		UserID:      nil,
		FlowID:      &data.flowID,
		Identifier:  identifier,
		Purpose:     purpose,
		CodeHash:    codeHash,
		Attempts:    0,
		MaxAttempts: data.maxAttempts,
		IPAddress:   &data.ipAddress,
		ExpiresAt:   data.now.Add(data.ttl),
		CreatedAt:   data.now,
	}

	err = a.event.PublishEventRegistration(ctx, EventRegistrationData{
		Name:     data.name,
		Channel:  channel,
		Identity: identifier,
		Code:     rawCode,
	})

	return &challenge, err
}

func (a *Application) issueRegistrationChallenges(
	ctx context.Context,
	data registrationChallengeData,
	email, phone string,
) ([]domain.VerificationChallenge, error) {
	var challenges []domain.VerificationChallenge

	if email != "" {
		challenge, err := a.issueRegistrationChallenge(
			ctx,
			data,
			email,
			channelEmail,
			domain.VerificationPurposeEmailVerification,
		)
		if err != nil {
			slog.ErrorContext(ctx, "failed to create email verification code", "error", err)

			return nil, goerror.NewServer(err)
		}

		challenges = append(challenges, *challenge)
	}

	if phone != "" {
		challenge, err := a.issueRegistrationChallenge(
			ctx,
			data,
			phone,
			channelPhone,
			domain.VerificationPurposePhoneVerification,
		)
		if err != nil {
			slog.ErrorContext(ctx, "failed to create phone verification code", "error", err)

			return nil, goerror.NewServer(err)
		}

		challenges = append(challenges, *challenge)
	}

	return challenges, nil
}
