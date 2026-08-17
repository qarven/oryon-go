package application

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strconv"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

type FinishPasskeyRegistrationInput struct {
	FlowID                  string `validate:"required"`
	AttestationResponseJSON string `validate:"required"`
	IPAddress               *string
	UserAgent               *string
}

type FinishPasskeyRegistrationOutput struct {
	Passkey domain.Passkey
}

func (a *Application) FinishPasskeyRegistration(ctx context.Context, input FinishPasskeyRegistrationInput) (*FinishPasskeyRegistrationOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "FinishPasskeyRegistration")
	defer span.End()

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	claims := jwt.GetAuth(ctx)
	if claims == nil {
		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
	}

	userID := claims.UserID

	flowID, err := strconv.ParseInt(input.FlowID, 10, 64)
	if err != nil {
		return nil, goerror.NewBusiness("invalid flow_id", goerror.CodeInvalidInput)
	}

	flow, err := a.repo.GetAuthFlowByID(ctx, flowID)
	if err != nil {
		return nil, goerror.NewBusiness("flow not found", goerror.CodeNotFound)
	}

	if flow.UserID == nil || *flow.UserID != userID {
		return nil, goerror.NewBusiness("flow does not belong to user", goerror.CodeForbidden)
	}

	challenge, err := a.cache.GetPasskeyChallenge(ctx, flowID)
	if err != nil {
		return nil, goerror.NewBusiness("challenge not found or expired", goerror.CodeInvalidInput)
	}

	// Parse attestationResponseJSON to extract credentialId and publicKey (mock)
	var att map[string]any
	if err := json.Unmarshal([]byte(input.AttestationResponseJSON), &att); err != nil {
		return nil, goerror.NewBusiness("invalid attestation response", goerror.CodeInvalidInput)
	}

	// For stub, generate random credentialId and publicKey if not provided
	credIDStr, _ := att["credentialId"].(string)
	var credID []byte
	if credIDStr != "" {
		credID, _ = base64.RawURLEncoding.DecodeString(credIDStr)
		if len(credID) == 0 {
			credID = []byte(credIDStr)
		}
	}

	if len(credID) == 0 {
		credID = make([]byte, 32)
		_, _ = rand.Read(credID)
	}

	pubKeyStr, _ := att["publicKey"].(string)
	var pubKey []byte
	if pubKeyStr != "" {
		pubKey, _ = base64.RawURLEncoding.DecodeString(pubKeyStr)
		if len(pubKey) == 0 {
			pubKey = []byte(pubKeyStr)
		}
	}

	if len(pubKey) == 0 {
		pubKey = make([]byte, 64)
		_, _ = rand.Read(pubKey)
	}

	name := "passkey"
	if flow.Context != nil {
		if v, ok := flow.Context["passkey_name"].(string); ok && v != "" {
			name = v
		}
	}

	now := a.clock.Now()
	pkID := a.uid.Generate()

	pk, err := domain.NewPasskey(pkID, userID, credID, pubKey, name, now)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	// Optional fields from attestation
	if aaguid, ok := att["aaguid"].(string); ok {
		pk.AAGUID = &aaguid
	}

	if transports, ok := att["transports"].([]any); ok {
		for _, t := range transports {
			if s, ok := t.(string); ok {
				pk.Transports = append(pk.Transports, s)
			}
		}
	}

	if err := a.repo.CreatePasskey(ctx, *pk); err != nil {
		return nil, goerror.NewServer(err)
	}

	// Also create MFA factor for webauthn if not exists? Optionally
	factorID := a.uid.Generate()
	factor, _ := domain.NewMfaFactor(factorID, userID, domain.MfaFactorTypeWebAuthn, name, now)
	if factor != nil {
		factor.Verify(now)
		_ = a.repo.CreateMfaFactor(ctx, *factor)
	}

	flow.Complete(now)
	_ = a.repo.UpdateAuthFlow(ctx, flow)
	_ = a.cache.DeletePasskeyChallenge(ctx, flowID)

	_ = challenge

	a.logSecurityEvent(ctx, &userID, "passkey.registered", nil, nil, map[string]any{"passkey_id": pkID})

	return &FinishPasskeyRegistrationOutput{Passkey: *pk}, nil
}
