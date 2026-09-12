package application

// import (
// 	"context"
// 	"encoding/base64"
// 	"encoding/json"
// 	"strconv"
// 	"time"

// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/goerror"
// )

// type FinishPasskeyLoginInput struct {
// 	FlowID                string `validate:"required"`
// 	AssertionResponseJSON string `validate:"required"`
// 	IPAddress             *string
// 	UserAgent             *string
// }

// type FinishPasskeyLoginOutput struct {
// 	Token        string
// 	RefreshToken string
// 	Session      domain.Session
// 	User         domain.User
// }

// func (a *Application) FinishPasskeyLogin(ctx context.Context, input FinishPasskeyLoginInput) (*FinishPasskeyLoginOutput, error) {
// 	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "FinishPasskeyLogin")
// 	defer span.End()

// 	if err := a.validator.Validate(input); err != nil {
// 		return nil, goerror.NewInvalidInput(err)
// 	}

// 	flowID, err := strconv.ParseInt(input.FlowID, 10, 64)
// 	if err != nil {
// 		return nil, goerror.NewBusiness("invalid flow_id", goerror.CodeInvalidInput)
// 	}

// 	flow, err := a.repo.GetAuthFlowByID(ctx, flowID)
// 	if err != nil {
// 		return nil, goerror.NewBusiness("flow not found", goerror.CodeNotFound)
// 	}

// 	challenge, err := a.cache.GetPasskeyChallenge(ctx, flowID)
// 	if err != nil {
// 		return nil, goerror.NewBusiness("challenge not found or expired", goerror.CodeInvalidInput)
// 	}

// 	var assertion map[string]any
// 	if err := json.Unmarshal([]byte(input.AssertionResponseJSON), &assertion); err != nil {
// 		return nil, goerror.NewBusiness("invalid assertion response", goerror.CodeInvalidInput)
// 	}

// 	credIDStr, _ := assertion["credentialId"].(string)
// 	if credIDStr == "" {
// 		credIDStr, _ = assertion["id"].(string)
// 	}

// 	if credIDStr == "" {
// 		return nil, goerror.NewBusiness("credentialId missing", goerror.CodeInvalidInput)
// 	}

// 	credID, err := base64.RawURLEncoding.DecodeString(credIDStr)
// 	if err != nil {
// 		credID = []byte(credIDStr)
// 	}

// 	pk, err := a.repo.GetPasskeyByCredentialID(ctx, credID)
// 	if err != nil {
// 		return nil, goerror.NewBusiness("passkey not found", goerror.CodeNotFound)
// 	}

// 	if pk.IsRevoked() {
// 		return nil, goerror.NewBusiness("passkey revoked", goerror.CodeForbidden)
// 	}

// 	// In real, verify signature using pk.PublicKey and challenge; here we mock success

// 	// Check flow user if set
// 	if flow.UserID != nil && *flow.UserID != pk.UserID {
// 		return nil, goerror.NewBusiness("passkey does not belong to flow user", goerror.CodeForbidden)
// 	}

// 	user, err := a.repo.GetUserByID(ctx, pk.UserID)
// 	if err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	if !user.CanAuthenticate() {
// 		return nil, goerror.NewBusiness("account is not active", goerror.CodeForbidden)
// 	}

// 	// Update passkey sign count if provided
// 	nowUpd := a.clock.Now()
// 	if sc, ok := assertion["signCount"].(float64); ok {
// 		_ = pk.UpdateSignCount(int64(sc), nowUpd)
// 		_ = a.repo.UpdatePasskey(ctx, pk)
// 	} else {
// 		pk.SignCount++
// 		pk.LastUsedAt = &nowUpd
// 		_ = a.repo.UpdatePasskey(ctx, pk)
// 	}

// 	now := a.clock.Now()
// 	flow.Complete(now)
// 	_ = a.repo.UpdateAuthFlow(ctx, flow)
// 	_ = a.cache.DeletePasskeyChallenge(ctx, flowID)

// 	primaryEmail, _ := a.getPrimaryEmail(ctx, user.ID)
// 	if primaryEmail == "" {
// 		primaryEmail = user.Name
// 	}

// 	access, refresh, err := a.issueTokens(ctx, user.ID, primaryEmail)
// 	if err != nil {
// 		return nil, err
// 	}

// 	sessionID := a.uid.Generate()
// 	tokenHash := hashToken(access)
// 	expiresAt := now.Add(a.config.GetMinute("modules.identity.jwt.access.ttl"))
// 	if expiresAt.IsZero() || expiresAt.Before(now) {
// 		expiresAt = now.Add(15 * time.Minute)
// 	}

// 	sess, _ := domain.NewSession(sessionID, user.ID, tokenHash, now, expiresAt, input.IPAddress, input.UserAgent)
// 	sess.MarkMFAVerified(now)
// 	_ = a.repo.CreateSession(ctx, *sess)

// 	refreshID := a.uid.Generate()
// 	refreshHash := hashToken(refresh)
// 	refreshExpires := now.Add(a.config.GetDay("modules.identity.jwt.refresh.ttl"))
// 	if refreshExpires.IsZero() || refreshExpires.Before(now) {
// 		refreshExpires = now.Add(7 * 24 * time.Hour)
// 	}

// 	rt, _ := domain.NewRefreshToken(refreshID, sessionID, refreshHash, now, refreshExpires, input.IPAddress)
// 	if rt != nil {
// 		_ = a.repo.CreateRefreshToken(ctx, *rt)
// 	}

// 	a.logSecurityEvent(ctx, &user.ID, "passkey.login", input.IPAddress, input.UserAgent, map[string]any{"passkey_id": pk.ID})
// 	a.logSecurityEvent(ctx, &user.ID, "login.success", input.IPAddress, input.UserAgent, map[string]any{"method": "passkey"})

// 	_ = challenge
// 	_ = time.Now

// 	return &FinishPasskeyLoginOutput{
// 		Token:        access,
// 		RefreshToken: refresh,
// 		Session:      *sess,
// 		User:         user,
// 	}, nil
// }
