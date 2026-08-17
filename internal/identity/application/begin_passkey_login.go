package application

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type BeginPasskeyLoginInput struct {
	Email     *string `validate:"omitempty,email"`
	FlowID    *string
	IPAddress *string
	UserAgent *string
}

type BeginPasskeyLoginOutput struct {
	RequestOptionsJSON string
	FlowID             string
	Flow               domain.AuthFlow
}

func (a *Application) BeginPasskeyLogin(ctx context.Context, input BeginPasskeyLoginInput) (*BeginPasskeyLoginOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "BeginPasskeyLogin")
	defer span.End()

	var userID *int64
	if input.Email != nil && *input.Email != "" {
		rec, err := a.repo.GetUserEmailByEmail(ctx, *input.Email)
		if err == nil {
			uid := rec.UserID
			userID = &uid
		}
	}

	now := a.clock.Now()
	flowID := a.uid.Generate()
	expires := now.Add(5 * time.Minute)

	flow, err := domain.NewAuthFlow(flowID, userID, domain.AuthFlowTypeLogin, domain.AuthFlowStatePendingVerification, input.IPAddress, input.UserAgent, map[string]any{}, now, expires)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	if err := a.repo.CreateAuthFlow(ctx, *flow); err != nil {
		return nil, goerror.NewServer(err)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, goerror.NewServer(err)
	}

	challenge := base64.RawURLEncoding.EncodeToString(raw)

	pc := domain.PasskeyChallenge{
		FlowID:    flowID,
		Challenge: challenge,
		Type:      "login",
		CreatedAt: now,
	}

	if userID != nil {
		pc.UserID = *userID
	}

	if err := a.cache.StorePasskeyChallenge(ctx, pc); err != nil {
		return nil, goerror.NewServer(err)
	}

	// Build request options
	allowCredentials := []any{}
	if userID != nil {
		passkeys, _ := a.repo.ListPasskeysByUserID(ctx, *userID, false)
		for _, pk := range passkeys {
			allowCredentials = append(allowCredentials, map[string]any{
				"type":       "public-key",
				"id":         base64.RawURLEncoding.EncodeToString(pk.CredentialID),
				"transports": pk.Transports,
			})
		}
	}

	options := map[string]any{
		"challenge":        challenge,
		"timeout":          60000,
		"userVerification": "preferred",
		"allowCredentials": allowCredentials,
		"rpId":             "localhost",
	}

	b, _ := json.Marshal(options)

	return &BeginPasskeyLoginOutput{
		RequestOptionsJSON: string(b),
		FlowID:             jsonNumber(flowID),
		Flow:               *flow,
	}, nil
}
