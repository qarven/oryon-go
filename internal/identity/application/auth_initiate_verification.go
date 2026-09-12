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
	initiateVerificationEmailKeyPrefix = "verification:req:email:"
	initiateVerificationPhoneKeyPrefix = "verification:req:phone:"
	initiateVerificationIPKeyPrefix    = "verification:req:ip:"
)

const (
	initiateChannelEmail = regCtxEmail
	initiateChannelPhone = regCtxPhone
)

type InitiateVerificationInput struct {
	Identifier string                     `validate:"required,min=3"`
	Purpose    domain.VerificationPurpose `validate:"required"`
	FlowID     *int64                     `validate:"omitempty,gt=0"`
	Meta       MetaInput                  `validate:"required"`
}

type InitiateVerificationOutput struct {
	Challenge *domain.VerificationChallenge
}

type ResendVerificationChallengeData struct {
	Flow      domain.AuthFlow
	Challenge domain.VerificationChallenge
}

func (a *Application) InitiateVerification(
	ctx context.Context,
	input InitiateVerificationInput,
) (*InitiateVerificationOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "InitiateVerification")
	defer span.End()

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	if !input.Purpose.IsValid() {
		return nil, goerror.NewInvalidInput(nil, "purpose", "unsupported verification purpose")
	}

	switch input.Purpose {
	case domain.VerificationPurposeEmailVerification, domain.VerificationPurposePhoneVerification:
		return a.initiateRegistrationVerification(ctx, input)
	case domain.VerificationPurposePasswordReset:
		return a.initiatePasswordReset(ctx, input)
	case domain.VerificationPurposeMFAVerification:
		return a.initiateMFAVerification(ctx, input)
	default:
		return nil, goerror.NewBusiness("unsupported verification purpose", goerror.CodeInvalidInput)
	}
}

// initiateRegistrationVerification re-issues an OTP challenge for a pending
// registration flow (resend code). The new challenge invalidates older
// sibling challenges for the same identifier+purpose and extends the flow
// expiry.
func (a *Application) initiateRegistrationVerification(
	ctx context.Context,
	input InitiateVerificationInput,
) (*InitiateVerificationOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "InitiateRegistrationVerification")
	defer span.End()

	var (
		identifier string
		channel    string
		eventType  domain.SecurityEventType
	)

	switch input.Purpose {
	case domain.VerificationPurposeEmailVerification:
		identifier = strings.ToLower(strings.TrimSpace(input.Identifier))

		if err := a.validator.Validate(struct {
			Email string `validate:"required,email"`
		}{Email: identifier}); err != nil {
			return nil, goerror.NewInvalidInput(err)
		}

		channel = initiateChannelEmail
		eventType = domain.SecurityEventTypeEmailVerificationRequested
	case domain.VerificationPurposePhoneVerification:
		identifier = strings.TrimSpace(input.Identifier)

		if err := a.validator.Validate(struct {
			Phone string `validate:"required,e164"`
		}{Phone: identifier}); err != nil {
			return nil, goerror.NewInvalidInput(err)
		}

		channel = initiateChannelPhone
		eventType = domain.SecurityEventTypePhoneVerificationRequested
	default:
		return nil, goerror.NewBusiness("unsupported verification purpose", goerror.CodeInvalidInput)
	}

	// Rate-limit before any lookup so enumeration probes are throttled too.
	keys := verificationRateLimitKeys(channel, identifier, input.Meta.IPAddress)

	if err := a.checkVerificationRateLimit(ctx, keys); err != nil {
		return nil, err
	}

	now := a.clock.Now()

	flow, err := a.resolveInitiateFlow(ctx, identifier, input.Purpose, input.FlowID)
	if err != nil {
		return nil, err
	}

	if flow.FlowType != domain.AuthFlowTypeRegistration {
		return nil, goerror.NewBusiness("flow is not for registration", goerror.CodeInvalidInput)
	}

	if flow.IsExpired(now) {
		return nil, goerror.NewBusiness("registration expired, please register again", goerror.CodeInvalidInput)
	}

	if flow.CompletedAt != nil || flow.FlowState.IsTerminal() {
		return nil, goerror.NewBusiness("registration already completed", goerror.CodeInvalidInput)
	}

	pending, err := pendingRegistrationFromFlow(flow)
	if err != nil {
		return nil, goerror.NewInvalidInput(nil, "flow", err.Error())
	}

	switch input.Purpose {
	case domain.VerificationPurposeEmailVerification:
		if pending.Email == "" || !strings.EqualFold(pending.Email, identifier) {
			return nil, goerror.NewBusiness("identifier does not match registration email", goerror.CodeInvalidInput)
		}

		if _, err := a.repo.GetUserEmailByEmail(ctx, identifier); err == nil {
			slog.WarnContext(ctx, "email already exists")

			return nil, goerror.NewBusiness("email already registered", goerror.CodeConflict)
		} else if !errors.Is(err, domain.ErrEmailNotFound) {
			slog.ErrorContext(ctx, "failed to get user email by email", "error", err)

			return nil, goerror.NewServer(err)
		}
	case domain.VerificationPurposePhoneVerification:
		if pending.Phone == "" || pending.Phone != identifier {
			return nil, goerror.NewBusiness("identifier does not match registration phone", goerror.CodeInvalidInput)
		}

		if _, err := a.repo.GetUserPhoneByPhone(ctx, identifier); err == nil {
			slog.WarnContext(ctx, "phone already exists")

			return nil, goerror.NewBusiness("phone already registered", goerror.CodeConflict)
		} else if !errors.Is(err, domain.ErrPhoneNotFound) {
			slog.ErrorContext(ctx, "failed to get user phone by phone number", "error", err)

			return nil, goerror.NewServer(err)
		}
	default:
		return nil, goerror.NewBusiness("unsupported verification purpose", goerror.CodeInvalidInput)
	}

	return a.finishInitiateVerification(ctx, now, input.Meta, finishInitiateParams{
		flow:       flow,
		userID:     nil,
		identifier: identifier,
		purpose:    input.Purpose,
		eventType:  eventType,
		isResend:   true,
		publish: func(ctx context.Context, code string) error {
			return a.event.PublishEventRegistration(ctx, EventRegistrationData{
				Name:     pending.Name,
				Channel:  channel,
				Identity: identifier,
				Code:     code,
			})
		},
	})
}

// verificationRateLimitKeys builds the fixed-window rate-limit keys for a
// verification request: one per identifier channel plus one per IP.
func verificationRateLimitKeys(channel string, identifier string, ipAddress string) []string {
	keys := []string{}
	if channel == initiateChannelEmail {
		keys = append(keys, initiateVerificationEmailKeyPrefix+identifier)
	} else {
		keys = append(keys, initiateVerificationPhoneKeyPrefix+identifier)
	}

	if strings.TrimSpace(ipAddress) != "" {
		keys = append(keys, initiateVerificationIPKeyPrefix+ipAddress)
	}

	return keys
}

// checkVerificationRateLimit increments fixed-window counters for each key
// and rejects the request once any counter exceeds the configured maximum.
func (a *Application) checkVerificationRateLimit(ctx context.Context, keys []string) error {
	rateLimitMax := a.config.GetInt("modules.identity.verification.rate_limit_max")
	rateWindow := a.config.GetMinute("modules.identity.verification.rate_limit_window")

	for _, key := range keys {
		count, err := a.cache.IncrementVerificationRequest(ctx, key, rateWindow)
		if err != nil {
			slog.ErrorContext(ctx, "failed to increment verification rate limit", "error", err)

			return goerror.NewServer(err)
		}

		if count > int64(rateLimitMax) {
			slog.WarnContext(ctx, "verification rate limit exceeded")

			return goerror.NewBusiness("too many requests", goerror.CodeTooManyRequest)
		}
	}

	return nil
}

// mintVerificationChallenge generates a fresh 6-digit OTP challenge. The raw
// code is returned alongside for delivery; only its hash is persisted.
func (a *Application) mintVerificationChallenge(
	now time.Time,
	userID *int64,
	flowID *int64,
	identifier string,
	purpose domain.VerificationPurpose,
	ipAddress string,
) (domain.VerificationChallenge, string, error) {
	rawCode, err := generate6DigitCode()
	if err != nil {
		return domain.VerificationChallenge{}, "", err
	}

	codeHash, err := a.sha256.Hash(rawCode)
	if err != nil {
		return domain.VerificationChallenge{}, "", err
	}

	maxAttempts := int16(a.config.GetInt("modules.identity.verification.max_attempts"))
	challengeTTL := a.config.GetMinute("modules.identity.verification.ttl")

	challenge := domain.VerificationChallenge{
		ID:          a.uid.Generate(),
		UserID:      userID,
		FlowID:      flowID,
		Identifier:  identifier,
		Purpose:     purpose,
		CodeHash:    codeHash,
		Attempts:    0,
		MaxAttempts: maxAttempts,
		IPAddress:   &ipAddress,
		ExpiresAt:   now.Add(challengeTTL),
		CreatedAt:   now,
	}

	return challenge, rawCode, nil
}

// finishInitiateParams carries the per-purpose details needed to mint,
// persist, deliver, and audit a verification challenge.
type finishInitiateParams struct {
	flow       *domain.AuthFlow
	userID     *int64
	identifier string
	purpose    domain.VerificationPurpose
	eventType  domain.SecurityEventType
	isResend   bool
	publish    func(ctx context.Context, code string) error
}

// finishInitiateVerification mints a challenge for the flow, persists it
// (resending on an existing flow or creating a new one), publishes the
// delivery event, and audits the request.
func (a *Application) finishInitiateVerification(
	ctx context.Context,
	now time.Time,
	meta MetaInput,
	params finishInitiateParams,
) (*InitiateVerificationOutput, error) {
	challenge, rawCode, err := a.mintVerificationChallenge(
		now,
		params.userID,
		&params.flow.ID,
		params.identifier,
		params.purpose,
		meta.IPAddress,
	)
	if err != nil {
		slog.ErrorContext(ctx, "failed to mint verification challenge", "error", err)

		return nil, goerror.NewServer(err)
	}

	if params.isResend {
		params.flow.ExpiresAt = now.Add(a.config.GetMinute("modules.identity.flow.ttl"))

		if err := a.repo.ResendVerificationChallenge(ctx, ResendVerificationChallengeData{
			Flow:      *params.flow,
			Challenge: challenge,
		}); err != nil {
			slog.ErrorContext(ctx, "failed to resend verification challenge", "error", err)

			return nil, goerror.NewServer(err)
		}
	} else if err := a.repo.CreateFlowWithChallenge(ctx, *params.flow, challenge); err != nil {
		slog.ErrorContext(ctx, "failed to create verification flow", "error", err)

		return nil, goerror.NewServer(err)
	}

	if err := params.publish(ctx, rawCode); err != nil {
		slog.ErrorContext(ctx, "failed to publish verification event", "error", err)

		return nil, goerror.NewServer(err)
	}

	a.logSecurityEvent(
		params.userID,
		params.eventType,
		meta,
		map[string]any{"flow_id": params.flow.ID, "identifier": params.identifier},
	)

	return &InitiateVerificationOutput{Challenge: &challenge}, nil
}

// ensureInitiateFlowUsable validates that a flow is a live, non-terminal
// flow of the expected type, optionally owned by the given user. Name is the
// human-readable flow kind used in error messages.
func ensureInitiateFlowUsable(
	now time.Time,
	flow *domain.AuthFlow,
	expected domain.AuthFlowType,
	ownerID *int64,
	name string,
) error {
	if flow.FlowType != expected {
		return goerror.NewBusiness("flow is not for "+name, goerror.CodeInvalidInput)
	}

	if ownerID != nil && (flow.UserID == nil || *flow.UserID != *ownerID) {
		return goerror.NewBusiness("flow does not belong to user", goerror.CodeInvalidInput)
	}

	if flow.IsExpired(now) {
		return goerror.NewBusiness(name+" expired, please request again", goerror.CodeInvalidInput)
	}

	if flow.CompletedAt != nil || flow.FlowState.IsTerminal() {
		return goerror.NewBusiness(name+" already completed", goerror.CodeInvalidInput)
	}

	return nil
}

// resolveInitiateFlow loads the registration flow a resend belongs to. When a
// flow id is supplied it is used directly; otherwise the latest pending
// challenge for the identifier+purpose provides the flow.
func (a *Application) resolveInitiateFlow(
	ctx context.Context,
	identifier string,
	purpose domain.VerificationPurpose,
	flowID *int64,
) (*domain.AuthFlow, error) {
	if flowID != nil {
		return a.getInitiateFlow(ctx, *flowID)
	}

	pendings, err := a.repo.ListPendingChallengesByIdentifier(ctx, identifier, purpose)
	if err != nil {
		slog.ErrorContext(ctx, "failed to list verification challenges", "error", err)

		return nil, goerror.NewServer(err)
	}

	for i := range pendings {
		if pendings[i].FlowID != nil {
			return a.getInitiateFlow(ctx, *pendings[i].FlowID)
		}
	}

	return nil, goerror.NewBusiness("verification not found, please register first", goerror.CodeNotFound)
}

func (a *Application) getInitiateFlow(ctx context.Context, flowID int64) (*domain.AuthFlow, error) {
	fetchedFlow, err := a.repo.GetAuthFlowByID(ctx, flowID)
	if errors.Is(err, domain.ErrAuthFlowNotFound) {
		return nil, goerror.NewBusiness("verification flow not found", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get auth flow", "error", err)

		return nil, goerror.NewServer(err)
	}

	return fetchedFlow, nil
}
