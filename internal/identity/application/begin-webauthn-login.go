package application

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type BeginWebAuthnLoginInput struct {
	FlowID domain.ID `validate:"required"`
	Meta   MetaInput `validate:"required"`
}

type BeginWebAuthnLoginOutput struct {
	Flow               domain.AuthFlow
	RequestOptionsJSON string
}

func (a *Application) BeginWebAuthnLogin(
	ctx context.Context,
	input BeginWebAuthnLoginInput,
) (*BeginWebAuthnLoginOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "BeginWebAuthnLogin")
	defer span.End()

	err := a.validator.Validate(input)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	flow, user, _, err := a.loadMfaLoginFlow(ctx, input.FlowID)
	if err != nil {
		return nil, err
	}

	_, err = a.findLoginMfaFactor(ctx, user.ID, domain.MfaFactorTypeWebAuthn)
	if err != nil {
		return nil, err
	}

	passkeys, err := a.repo.ListPasskeysByUserID(ctx, user.ID, false)
	if err != nil {
		slog.ErrorContext(ctx, "failed to list passkeys by user id", "error", err)

		return nil, goerror.NewServer(err)
	}

	if len(passkeys) == 0 {
		slog.WarnContext(ctx, "user has no active passkey", "user_id", user.ID)

		return nil, goerror.NewBusiness("no passkey registered", goerror.CodeUnauthorized)
	}

	assertion, session, err := a.webauthn.BeginLogin(&webauthnUser{user: user, passkeys: passkeys})
	if err != nil {
		slog.ErrorContext(ctx, "failed to begin webauthn login", "user_id", user.ID, "error", err)

		return nil, goerror.NewServer(err)
	}

	optionsJSON, err := json.Marshal(assertion.Response)
	if err != nil {
		slog.ErrorContext(ctx, "failed to marshal webauthn request options", "user_id", user.ID, "error", err)

		return nil, goerror.NewServer(err)
	}

	err = setWebAuthnSession(flow, session)
	if err != nil {
		slog.ErrorContext(ctx, "failed to encode webauthn session", "flow_id", flow.ID, "error", err)

		return nil, goerror.NewServer(err)
	}

	err = a.repo.UpdateAuthFlowContext(ctx, flow.ID, flow.Context)
	if err != nil {
		slog.ErrorContext(ctx, "failed to store webauthn session", "flow_id", flow.ID, "error", err)

		return nil, goerror.NewServer(err)
	}

	return &BeginWebAuthnLoginOutput{
		Flow:               *flow,
		RequestOptionsJSON: string(optionsJSON),
	}, nil
}
