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

type EventPasswordResetData struct {
	Name     string `json:"name"`
	Code     string `json:"code"`
	Identity string `json:"identity"`
	Channel  string `json:"channel"` // email
}

// initiatePasswordReset issues a password-reset OTP for a registered email.
// A new recovery flow is created unless a flow id for resending is supplied.
// Unknown or deleted accounts return an empty success so account existence
// cannot be probed.
func (a *Application) initiatePasswordReset(
	ctx context.Context,
	input InitiateVerificationInput,
) (*InitiateVerificationOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "InitiatePasswordReset")
	defer span.End()

	email := strings.ToLower(strings.TrimSpace(input.Identifier))

	if err := a.validator.Validate(struct {
		Email string `validate:"required,email"`
	}{Email: email}); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	// Rate-limit before any lookup so enumeration probes are throttled too.
	keys := verificationRateLimitKeys(initiateChannelEmail, email, input.Meta.IPAddress)

	if err := a.checkVerificationRateLimit(ctx, keys); err != nil {
		return nil, err
	}

	user, found, err := a.resolvePasswordResetUser(ctx, email)
	if err != nil {
		return nil, err
	}

	if !found {
		a.logSecurityEvent(
			nil,
			domain.SecurityEventTypePasswordResetRequested,
			input.Meta,
			map[string]any{"identifier": email},
		)

		return &InitiateVerificationOutput{}, nil
	}

	now := a.clock.Now()

	flow, err := a.resolvePasswordResetFlow(ctx, now, user, email, input.Meta, input.FlowID)
	if err != nil {
		return nil, err
	}

	return a.finishInitiateVerification(ctx, now, input.Meta, finishInitiateParams{
		flow:       flow,
		userID:     &user.ID,
		identifier: email,
		purpose:    domain.VerificationPurposePasswordReset,
		eventType:  domain.SecurityEventTypePasswordResetRequested,
		isResend:   input.FlowID != nil,
		publish: func(ctx context.Context, code string) error {
			return a.event.PublishEventPasswordReset(ctx, EventPasswordResetData{
				Name:     user.Name,
				Channel:  initiateChannelEmail,
				Identity: email,
				Code:     code,
			})
		},
	})
}

// resolvePasswordResetUser loads the account for a reset request. Found is
// false for unknown or deleted accounts, which must receive an empty success
// so account existence cannot be probed.
func (a *Application) resolvePasswordResetUser(
	ctx context.Context,
	email string,
) (*domain.User, bool, error) {
	userEmail, err := a.repo.GetUserEmailByEmail(ctx, email)
	if errors.Is(err, domain.ErrEmailNotFound) {
		return nil, false, nil
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user email by email", "error", err)

		return nil, false, goerror.NewServer(err)
	}

	user, err := a.repo.GetUserByID(ctx, userEmail.UserID)
	if errors.Is(err, domain.ErrUserNotFound) {
		return nil, false, nil
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "error", err)

		return nil, false, goerror.NewServer(err)
	}

	if user.IsDeleted() {
		return nil, false, nil
	}

	return user, true, nil
}

// resolvePasswordResetFlow returns the recovery flow a reset belongs to: the
// supplied flow for resends, or a fresh recovery flow for new requests.
func (a *Application) resolvePasswordResetFlow(
	ctx context.Context,
	now time.Time,
	user *domain.User,
	email string,
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
			domain.AuthFlowTypeRecovery,
			&user.ID,
			"password reset",
		); err != nil {
			return nil, err
		}

		return fetched, nil
	}

	flowIDNew := a.uid.Generate()

	return &domain.AuthFlow{
		ID:        flowIDNew,
		UserID:    &user.ID,
		FlowType:  domain.AuthFlowTypeRecovery,
		FlowState: domain.AuthFlowStatePendingVerification,
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
		Context:   map[string]any{"email": email},
		ExpiresAt: now.Add(a.config.GetMinute("modules.identity.flow.ttl")),
		CreatedAt: now,
	}, nil
}
