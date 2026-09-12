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

type EventMFAVerificationData struct {
	Name     string `json:"name"`
	Code     string `json:"code"`
	Identity string `json:"identity"`
	Channel  string `json:"channel"` // email, phone
}

// initiateMFAVerification issues an OTP to one of the caller's own verified
// contacts as a step-up second factor. The caller must be authenticated and
// the contact must be verified. A new step-up flow is created unless a flow
// id for resending is supplied.
func (a *Application) initiateMFAVerification(
	ctx context.Context,
	input InitiateVerificationInput,
) (*InitiateVerificationOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "InitiateMFAVerification")
	defer span.End()

	claims := jwt.GetAuth(ctx)
	if claims == nil {
		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
	}

	identifier, channel, err := a.detectMFAChannel(strings.TrimSpace(input.Identifier))
	if err != nil {
		return nil, err
	}

	keys := verificationRateLimitKeys(channel, identifier, input.Meta.IPAddress)

	if err := a.checkVerificationRateLimit(ctx, keys); err != nil {
		return nil, err
	}

	user, err := a.loadActiveUser(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}

	// The OTP may only go to a verified contact owned by the caller.
	if err := a.verifyMFAContact(ctx, user, identifier, channel); err != nil {
		return nil, err
	}

	now := a.clock.Now()

	flow, err := a.resolveMFAFlow(ctx, now, user, identifier, channel, input.Meta, input.FlowID)
	if err != nil {
		return nil, err
	}

	return a.finishInitiateVerification(ctx, now, input.Meta, finishInitiateParams{
		flow:       flow,
		userID:     &user.ID,
		identifier: identifier,
		purpose:    domain.VerificationPurposeMFAVerification,
		eventType:  domain.SecurityEventTypeMFAVerificationRequested,
		isResend:   input.FlowID != nil,
		publish: func(ctx context.Context, code string) error {
			return a.event.PublishEventMFAVerification(ctx, EventMFAVerificationData{
				Name:     user.Name,
				Channel:  channel,
				Identity: identifier,
				Code:     code,
			})
		},
	})
}

// detectMFAChannel normalizes the identifier and determines its channel by
// format: anything containing '@' is treated as an email, otherwise as an
// E.164 phone number.
func (a *Application) detectMFAChannel(raw string) (string, string, error) {
	if strings.Contains(raw, "@") {
		identifier := strings.ToLower(raw)

		if err := a.validator.Validate(struct {
			Email string `validate:"required,email"`
		}{Email: identifier}); err != nil {
			return "", "", goerror.NewInvalidInput(err)
		}

		return identifier, initiateChannelEmail, nil
	}

	if err := a.validator.Validate(struct {
		Phone string `validate:"required,e164"`
	}{Phone: raw}); err != nil {
		return "", "", goerror.NewInvalidInput(err)
	}

	return raw, initiateChannelPhone, nil
}

// loadActiveUser loads the user and ensures the account can authenticate.
func (a *Application) loadActiveUser(ctx context.Context, userID int64) (*domain.User, error) {
	user, err := a.repo.GetUserByID(ctx, userID)
	if errors.Is(err, domain.ErrUserNotFound) {
		return nil, goerror.NewBusiness("user not found", goerror.CodeUnauthorized)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "error", err)

		return nil, goerror.NewServer(err)
	}

	if user.IsDeleted() {
		slog.WarnContext(ctx, "user is already deleted")

		return nil, goerror.NewBusiness("account is deleted", goerror.CodeForbidden)
	}

	if !user.CanAuthenticate() {
		slog.WarnContext(ctx, "user status is not active")

		return nil, goerror.NewBusiness("account is not active", goerror.CodeForbidden)
	}

	return user, nil
}

// verifyMFAContact ensures the identifier is a verified contact owned by the
// caller. Unknown or foreign contacts report not found so ownership cannot
// be probed through an authenticated session.
func (a *Application) verifyMFAContact(
	ctx context.Context,
	user *domain.User,
	identifier string,
	channel string,
) error {
	switch channel {
	case initiateChannelEmail:
		rec, err := a.repo.GetUserEmailByEmail(ctx, identifier)
		if errors.Is(err, domain.ErrEmailNotFound) ||
			(err == nil && rec.UserID != user.ID) {
			return goerror.NewBusiness("verified contact not found", goerror.CodeNotFound)
		}

		if err != nil {
			slog.ErrorContext(ctx, "failed to get user email by email", "error", err)

			return goerror.NewServer(err)
		}

		if !rec.IsVerified() {
			return goerror.NewBusiness("contact is not verified", goerror.CodeInvalidInput)
		}
	case initiateChannelPhone:
		rec, err := a.repo.GetUserPhoneByPhone(ctx, identifier)
		if errors.Is(err, domain.ErrPhoneNotFound) ||
			(err == nil && rec.UserID != user.ID) {
			return goerror.NewBusiness("verified contact not found", goerror.CodeNotFound)
		}

		if err != nil {
			slog.ErrorContext(ctx, "failed to get user phone by phone number", "error", err)

			return goerror.NewServer(err)
		}

		if !rec.IsVerified() {
			return goerror.NewBusiness("contact is not verified", goerror.CodeInvalidInput)
		}
	default:
		return goerror.NewBusiness("unsupported verification channel", goerror.CodeInvalidInput)
	}

	return nil
}

// resolveMFAFlow returns the step-up flow a verification belongs to: the
// supplied flow for resends, or a fresh step-up flow for new requests.
func (a *Application) resolveMFAFlow(
	ctx context.Context,
	now time.Time,
	user *domain.User,
	identifier string,
	channel string,
	meta MetaInput,
	flowID *int64,
) (*domain.AuthFlow, error) {
	if flowID != nil {
		fetched, err := a.getInitiateFlow(ctx, *flowID)
		if err != nil {
			return nil, err
		}

		if err := ensureInitiateFlowUsable(
			now,
			fetched,
			domain.AuthFlowTypeStepUpMFA,
			&user.ID,
			"mfa verification",
		); err != nil {
			return nil, err
		}

		return fetched, nil
	}

	flowIDNew := a.uid.Generate()

	return &domain.AuthFlow{
		ID:        flowIDNew,
		UserID:    &user.ID,
		FlowType:  domain.AuthFlowTypeStepUpMFA,
		FlowState: domain.AuthFlowStatePendingVerification,
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
		Context:   map[string]any{"identifier": identifier, "channel": channel},
		ExpiresAt: now.Add(a.config.GetMinute("modules.identity.flow.ttl")),
		CreatedAt: now,
	}, nil
}
