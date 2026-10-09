package application

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type ResendRegistrationCodeInput struct {
	FlowID domain.ID `validate:"required"`
	Meta   MetaInput `validate:"required"`
}

type ResendRegistrationCodeOutput struct {
	Flow domain.AuthFlow
}

type resendTarget struct {
	identifier string
	channel    string
	purpose    domain.VerificationPurpose
}

func (a *Application) ResendRegistrationCode(
	ctx context.Context,
	input ResendRegistrationCodeInput,
) (*ResendRegistrationCodeOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "ResendRegistrationCode")
	defer span.End()

	err := a.validator.Validate(input)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	flow, pending, err := a.loadResendableFlow(ctx, input.FlowID)
	if err != nil {
		return nil, err
	}

	err = a.checkVerificationRateLimit(ctx, pending.Email, pending.Phone, input.Meta.IPAddress)
	if err != nil {
		return nil, err
	}

	targets := []resendTarget{}
	if pending.Email != "" {
		targets = append(targets, resendTarget{
			identifier: pending.Email,
			channel:    channelEmail,
			purpose:    domain.VerificationPurposeEmailVerification,
		})
	}

	if pending.Phone != "" {
		targets = append(targets, resendTarget{
			identifier: pending.Phone,
			channel:    channelPhone,
			purpose:    domain.VerificationPurposePhoneVerification,
		})
	}

	challenges, rawCodes, err := a.newResendChallenges(
		ctx,
		targets,
		flow.ID,
		input.Meta.IPAddress,
		a.clock.Now(),
		int16(a.config.GetInt("modules.identity.verification.max_attempts")),
		a.config.GetMinute("modules.identity.verification.ttl"),
	)
	if err != nil {
		return nil, err
	}

	err = a.repo.ResendRegistrationCode(ctx, challenges)
	if err != nil {
		slog.ErrorContext(ctx, "failed to resend registration code", "flow_id", flow.ID, "error", err)

		return nil, goerror.NewServer(err)
	}

	for i, target := range targets {
		err := a.event.PublishEventRegistration(ctx, EventRegistrationData{
			Name:     pending.Name,
			Channel:  target.channel,
			Identity: target.identifier,
			Code:     rawCodes[i],
		})
		if err != nil {
			slog.ErrorContext(
				ctx,
				"failed to publish resend registration event",
				"identifier", target.identifier,
				"channel", target.channel,
				"error", err,
			)

			return nil, goerror.NewServer(err)
		}
	}

	a.securityEvent(domain.SecurityEventTypeRegistrationRequested).
		WithMeta(input.Meta).
		With("flow_id", flow.ID).
		With("email", pending.Email).
		With("phone", pending.Phone).
		With("resend", true).
		Emit(ctx)

	return &ResendRegistrationCodeOutput{Flow: *flow}, nil
}

func (a *Application) loadResendableFlow(
	ctx context.Context,
	flowID domain.ID,
) (*domain.AuthFlow, pendingRegistration, error) {
	flow, err := a.repo.GetAuthFlowByID(ctx, flowID)
	if errors.Is(err, domain.ErrAuthFlowNotFound) {
		slog.WarnContext(ctx, "registration flow not found")

		return nil, pendingRegistration{}, goerror.NewBusiness("registration flow not found", goerror.CodeNotFound)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get auth flow", "error", err)

		return nil, pendingRegistration{}, goerror.NewServer(err)
	}

	if flow.FlowType != domain.AuthFlowTypeRegistration {
		slog.WarnContext(ctx, "flow is not for registration", "flow_type", flow.FlowType)

		return nil, pendingRegistration{}, goerror.NewBusiness("flow is not for registration", goerror.CodeInvalidInput)
	}

	if flow.IsExpired(a.clock.Now()) {
		slog.WarnContext(ctx, "registration flow expired")

		return nil, pendingRegistration{}, goerror.NewBusiness(
			"registration expired, please register again",
			goerror.CodeInvalidInput,
		)
	}

	if flow.CompletedAt != nil || flow.FlowState.IsTerminal() {
		slog.WarnContext(ctx, "registration already completed")

		return nil, pendingRegistration{}, goerror.NewBusiness("registration already completed", goerror.CodeInvalidInput)
	}

	pending, err := a.pendingRegistrationFromFlow(flow)
	if err != nil {
		slog.WarnContext(ctx, "invalid registration flow data", "error", err)

		return nil, pendingRegistration{}, goerror.NewInvalidInput(nil, "flow", err.Error())
	}

	return flow, pending, nil
}

func (a *Application) newResendChallenges(
	ctx context.Context,
	targets []resendTarget,
	flowID domain.ID,
	ipAddress string,
	now time.Time,
	maxAttempts int16,
	ttl time.Duration,
) ([]domain.VerificationChallenge, []string, error) {
	challenges := make([]domain.VerificationChallenge, 0, len(targets))
	rawCodes := make([]string, 0, len(targets))

	for _, target := range targets {
		rawCode, err := generate6DigitCode()
		if err != nil {
			slog.ErrorContext(ctx, "failed to generate verification code", "flow_id", flowID, "error", err)

			return nil, nil, goerror.NewServer(err)
		}

		codeHash, err := a.sha256.Hash(rawCode)
		if err != nil {
			slog.ErrorContext(ctx, "failed to hash verification code", "flow_id", flowID, "error", err)

			return nil, nil, goerror.NewServer(err)
		}

		challenges = append(challenges, domain.VerificationChallenge{
			ID:          domain.IDFrom(a.uuid.Generate()),
			UserID:      nil,
			FlowID:      &flowID,
			Identifier:  target.identifier,
			Purpose:     target.purpose,
			CodeHash:    codeHash,
			Attempts:    0,
			MaxAttempts: maxAttempts,
			IPAddress:   &ipAddress,
			ExpiresAt:   now.Add(ttl),
			CreatedAt:   now,
		})
		rawCodes = append(rawCodes, rawCode)
	}

	return challenges, rawCodes, nil
}
