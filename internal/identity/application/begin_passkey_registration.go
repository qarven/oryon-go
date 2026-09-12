package application

// import (
// 	"context"
// 	"crypto/rand"
// 	"encoding/base64"
// 	"encoding/json"
// 	"time"

// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/goerror"
// 	"github.com/qarven/oryon-go/internal/pkg/jwt"
// )

// type BeginPasskeyRegistrationInput struct {
// 	Name      string  `validate:"required"`
// 	FlowID    *string `validate:"omitempty"`
// 	IPAddress *string
// 	UserAgent *string
// }

// type BeginPasskeyRegistrationOutput struct {
// 	CreationOptionsJSON string
// 	FlowID              string
// 	Flow                domain.AuthFlow
// }

// func (a *Application) BeginPasskeyRegistration(ctx context.Context, input BeginPasskeyRegistrationInput) (*BeginPasskeyRegistrationOutput, error) {
// 	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "BeginPasskeyRegistration")
// 	defer span.End()

// 	if err := a.validator.Validate(input); err != nil {
// 		return nil, goerror.NewInvalidInput(err)
// 	}

// 	claims := jwt.GetAuth(ctx)
// 	if claims == nil {
// 		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
// 	}

// 	userID := claims.UserID

// 	user, err := a.repo.GetUserByID(ctx, userID)
// 	if err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	now := a.clock.Now()
// 	flowID := a.uid.Generate()
// 	expires := now.Add(5 * time.Minute)

// 	flow, err := domain.NewAuthFlow(flowID, &userID, domain.AuthFlowTypeStepUpMFA, domain.AuthFlowStatePendingVerification, input.IPAddress, input.UserAgent, map[string]any{"passkey_name": input.Name}, now, expires)
// 	if err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	if err := a.repo.CreateAuthFlow(ctx, *flow); err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	// Generate challenge 32 bytes base64url
// 	raw := make([]byte, 32)
// 	if _, err := rand.Read(raw); err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	challenge := base64.RawURLEncoding.EncodeToString(raw)

// 	// Store in cache
// 	pc := domain.PasskeyChallenge{
// 		FlowID:    flowID,
// 		UserID:    userID,
// 		Challenge: challenge,
// 		Type:      "registration",
// 		CreatedAt: now,
// 	}

// 	if err := a.cache.StorePasskeyChallenge(ctx, pc); err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	// Build PublicKeyCredentialCreationOptions JSON stub
// 	options := map[string]any{
// 		"challenge": challenge,
// 		"rp": map[string]any{
// 			"name": a.config.GetString("modules.identity.mfa.totp.issuer"),
// 			"id":   "localhost",
// 		},
// 		"user": map[string]any{
// 			"id":          base64.RawURLEncoding.EncodeToString([]byte(user.Name)),
// 			"name":        user.Name,
// 			"displayName": user.Name,
// 		},
// 		"pubKeyCredParams": []map[string]any{
// 			{"type": "public-key", "alg": -7},
// 			{"type": "public-key", "alg": -257},
// 		},
// 		"timeout":            60000,
// 		"attestation":        "none",
// 		"excludeCredentials": []any{},
// 		"authenticatorSelection": map[string]any{
// 			"residentKey":        "preferred",
// 			"requireResidentKey": false,
// 			"userVerification":   "preferred",
// 		},
// 	}

// 	b, _ := json.Marshal(options)

// 	flowIDStr := string(rune(flowID)) // placeholder - will format properly
// 	// Use fmt
// 	flowIDStr = jsonNumber(flowID)

// 	return &BeginPasskeyRegistrationOutput{
// 		CreationOptionsJSON: string(b),
// 		FlowID:              flowIDStr,
// 		Flow:                *flow,
// 	}, nil
// }

// func jsonNumber(n int64) string {
// 	// simple decimal conversion without fmt to avoid import
// 	if n == 0 {
// 		return "0"
// 	}

// 	neg := n < 0
// 	if neg {
// 		n = -n
// 	}

// 	var buf [20]byte
// 	pos := len(buf)
// 	for n > 0 {
// 		pos--
// 		buf[pos] = byte('0' + n%10)
// 		n /= 10
// 	}

// 	if neg {
// 		pos--
// 		buf[pos] = '-'
// 	}

// 	return string(buf[pos:])
// }
