package application

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type CompleteWebAuthnLoginInput struct {
	FlowID                domain.ID `validate:"required"`
	AssertionResponseJSON string    `validate:"required"`
	Meta                  MetaInput `validate:"required"`
}

type CompleteWebAuthnLoginOutput struct {
	Token          string
	TokenExpiresIn int64
	RefreshToken   string
	User           domain.User
}

type webAuthnFinishData struct {
	Flow   *domain.AuthFlow
	User   *domain.User
	Factor *domain.MfaFactor
	Meta   MetaInput
	Now    time.Time
}

func (a *Application) CompleteWebAuthnLogin(
	ctx context.Context,
	input CompleteWebAuthnLoginInput,
) (*CompleteWebAuthnLoginOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "CompleteWebAuthnLogin")
	defer span.End()

	input.AssertionResponseJSON = strings.TrimSpace(input.AssertionResponseJSON)

	err := a.validator.Validate(input)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	flow, user, session, passkeys, now, err := a.loadWebAuthnCeremony(ctx, input.FlowID)
	if err != nil {
		return nil, err
	}

	if len(passkeys) == 0 {
		slog.WarnContext(ctx, "user has no active passkey", "user_id", user.ID)

		return nil, goerror.NewBusiness("no passkey registered", goerror.CodeUnauthorized)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(
		bytes.NewBufferString(input.AssertionResponseJSON),
	)
	if err != nil {
		slog.WarnContext(ctx, "invalid webauthn assertion response", "flow_id", flow.ID, "error", err)

		return nil, goerror.NewBusiness("invalid assertion", goerror.CodeUnauthorized)
	}

	adapter := &webauthnUser{user: user, passkeys: passkeys}

	credential, err := a.webauthn.ValidateLogin(adapter, *session, parsed)
	if err != nil {
		a.securityEvent(domain.SecurityEventTypeLoginFailed).
			ForUser(&user.ID).
			WithMeta(input.Meta).
			With("reason", "invalid_webauthn_assertion").
			With("flow_id", flow.ID).
			Emit(ctx)
		slog.WarnContext(ctx, "webauthn assertion verification failed", "flow_id", flow.ID, "error", err)

		return nil, goerror.NewBusiness("invalid assertion", goerror.CodeUnauthorized)
	}

	matched := findPasskey(passkeys, credential.ID)
	if matched == nil {
		slog.ErrorContext(ctx, "data integrity violation: verified credential not in passkey list",
			"flow_id", flow.ID, "user_id", user.ID)

		return nil, goerror.NewServer(errCredentialMismatch)
	}

	if credential.Authenticator.CloneWarning {
		slog.WarnContext(ctx, "webauthn clone warning",
			"flow_id", flow.ID, "user_id", user.ID, "passkey_id", matched.ID)
	}

	err = a.repo.UpdatePasskeyLogin(ctx, matched.ID, int64(credential.Authenticator.SignCount), now)
	if err != nil {
		slog.ErrorContext(ctx, "failed to update passkey sign count",
			"passkey_id", matched.ID, "error", err)

		return nil, goerror.NewServer(err)
	}

	factor, err := a.findLoginMfaFactor(ctx, user.ID, domain.MfaFactorTypeWebAuthn)
	if err != nil {
		return nil, err
	}

	return a.finishWebAuthnLogin(ctx, webAuthnFinishData{
		Flow:   flow,
		User:   user,
		Factor: factor,
		Meta:   input.Meta,
		Now:    now,
	})
}

func (a *Application) loadWebAuthnCeremony(
	ctx context.Context,
	flowID domain.ID,
) (*domain.AuthFlow, *domain.User, *webauthn.SessionData, []domain.Passkey, time.Time, error) {
	flow, user, now, err := a.loadMfaLoginFlow(ctx, flowID)
	if err != nil {
		return nil, nil, nil, nil, time.Time{}, err
	}

	session, err := webAuthnSessionFromFlow(flow)
	if errors.Is(err, ErrWebAuthnSessionMissing) {
		slog.WarnContext(ctx, "webauthn session missing", "flow_id", flow.ID)

		return nil, nil, nil, nil, time.Time{},
			goerror.NewBusiness("login session expired, restart login", goerror.CodeUnauthorized)
	}

	if err != nil {
		slog.ErrorContext(ctx, "webauthn session corrupt", "flow_id", flow.ID, "error", err)

		return nil, nil, nil, nil, time.Time{}, goerror.NewServer(err)
	}

	passkeys, err := a.repo.ListPasskeysByUserID(ctx, user.ID, false)
	if err != nil {
		slog.ErrorContext(ctx, "failed to list passkeys by user id", "error", err)

		return nil, nil, nil, nil, time.Time{}, goerror.NewServer(err)
	}

	return flow, user, session, passkeys, now, nil
}

func findPasskey(passkeys []domain.Passkey, credentialID []byte) *domain.Passkey {
	for _, passkey := range passkeys {
		if bytes.Equal(passkey.CredentialID, credentialID) {
			matched := passkey

			return &matched
		}
	}

	return nil
}

func (a *Application) finishWebAuthnLogin(
	ctx context.Context,
	data webAuthnFinishData,
) (*CompleteWebAuthnLoginOutput, error) {
	issue, err := a.issueTokens(ctx, data.User.ID)
	if err != nil {
		return nil, err
	}

	finished, err := a.finishMfaLogin(ctx, mfaLoginFinishData{
		Flow:   data.Flow,
		User:   data.User,
		Factor: data.Factor,
		Meta:   data.Meta,
		Now:    data.Now,
		issue:  issue,
	})
	if err != nil {
		return nil, err
	}

	a.securityEvent(domain.SecurityEventTypeLoginSuccess).
		ForUser(&data.User.ID).
		WithMeta(data.Meta).
		With("method", "webauthn").
		With("flow_id", data.Flow.ID).
		With("factor_type", data.Factor.Type).
		With("factor_id", data.Factor.ID).
		Emit(ctx)

	return &CompleteWebAuthnLoginOutput{
		Token:          finished.Token,
		TokenExpiresIn: finished.TokenExpiresIn,
		RefreshToken:   finished.RefreshToken,
		User:           finished.User,
	}, nil
}
