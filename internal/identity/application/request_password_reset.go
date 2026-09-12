package application

// import (
// 	"context"
// 	"crypto/rand"
// 	"encoding/hex"
// 	"fmt"
// 	"time"

// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/goerror"
// )

// type RequestPasswordResetInput struct {
// 	Email     string  `validate:"required,email"`
// 	IPAddress *string `validate:"omitempty,ip"`
// 	UserAgent *string
// }

// type RequestPasswordResetOutput struct {
// 	VerificationID *string
// }

// func (a *Application) RequestPasswordReset(ctx context.Context, input RequestPasswordResetInput) (*RequestPasswordResetOutput, error) {
// 	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "RequestPasswordReset")
// 	defer span.End()

// 	if err := a.validator.Validate(input); err != nil {
// 		return nil, goerror.NewInvalidInput(err)
// 	}

// 	// Avoid enumeration: always return success even if email not found
// 	userEmail, err := a.repo.GetUserEmailByEmail(ctx, input.Email)
// 	if err != nil {
// 		// email not found, still return empty success
// 		return &RequestPasswordResetOutput{}, nil
// 	}

// 	now := a.clock.Now()
// 	// Generate secure token 32 bytes hex
// 	raw := make([]byte, 32)
// 	if _, err := rand.Read(raw); err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	token := hex.EncodeToString(raw)
// 	hash := hashSHA256Raw(token)

// 	challengeID := a.uid.Generate()
// 	expires := now.Add(15 * time.Minute)

// 	var userID = userEmail.UserID
// 	vc, err := domain.NewVerificationChallenge(challengeID, &userID, nil, input.Email, domain.VerificationPurposePasswordReset, hash, 3, input.IPAddress, now, expires)
// 	if err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	if err := a.repo.CreateVerificationChallenge(ctx, *vc); err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	// Async send email (mock)
// 	a.goroutine.Go(context.Background(), func(ctx context.Context) error {
// 		// In real, send email with token via mail
// 		_ = token
// 		_ = time.Now
// 		return nil
// 	})

// 	a.logSecurityEvent(ctx, &userID, "password.reset_requested", input.IPAddress, input.UserAgent, map[string]any{"email": input.Email})

// 	vid := fmt.Sprintf("%d", challengeID)
// 	// In real prod we might not return vid to avoid enumeration, but for dev we do
// 	// To avoid enumeration, we could return nil if we want strict; but spec allows optional
// 	// We'll return verification id for existence case
// 	return &RequestPasswordResetOutput{VerificationID: &vid}, nil
// }
