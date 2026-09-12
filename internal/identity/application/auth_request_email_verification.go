package application

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

const (
	verificationRequestEmailKeyPrefix = "verification:req:email:"
	verificationRequestIPKeyPrefix    = "verification:req:ip:"
)

type RequestEmailVerificationInput struct {
	Email string    `validate:"required,email"`
	Meta  MetaInput `validate:"required"`
}

type RequestEmailVerificationOutput struct {
	Challenge *domain.VerificationChallenge
}

func (a *Application) RequestEmailVerification(ctx context.Context, input RequestEmailVerificationInput) (*RequestEmailVerificationOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "RequestEmailVerification")
	defer span.End()

	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	now := a.clock.Now()
	ttl := a.config.GetMinute("modules.identity.verification.ttl")
	maxAttempts := int16(a.config.GetInt("modules.identity.verification.max_attempts"))
	rateLimitMax := a.config.GetInt("modules.identity.verification.rate_limit_max")
	rateWindow := a.config.GetMinute("modules.identity.verification.rate_limit_window")

	// Rate-limit before any lookup so enumeration probes are throttled too.
	// Both dimensions must pass; counters increment even for unknown emails
	// to keep the response indistinguishable (generic success).
	keys := []string{verificationRequestEmailKeyPrefix + input.Email}
	if strings.TrimSpace(input.Meta.IPAddress) != "" {
		keys = append(keys, verificationRequestIPKeyPrefix+input.Meta.IPAddress)
	}

	for _, key := range keys {
		count, err := a.cache.IncrementVerificationRequest(ctx, key, rateWindow)
		if err != nil {
			slog.ErrorContext(ctx, "failed to increment verification rate limit", "error", err)
			return nil, goerror.NewServer(err)
		}

		if count > int64(rateLimitMax) {
			slog.WarnContext(ctx, "email verification rate limit exceeded")
			return nil, goerror.NewBusiness("too many requests", goerror.CodeTooManyRequest)
		}
	}

	rawCode, err := generateEmailVerificationCode()
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate verification code", "error", err)
		return nil, goerror.NewServer(err)
	}

	codeHash, err := a.sha256.Hash(rawCode)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash verification code", "error", err)
		return nil, goerror.NewServer(err)
	}

	emailRec, err := a.repo.GetUserEmailByEmail(ctx, input.Email)
	if err != nil {
		// Pending verify-before-create registration: return the live challenge
		// so the client can call VerifyEmail without triggering a second OTP.
		// The OTP was already sent when the registration flow was created.
		if errors.Is(err, domain.ErrEmailNotFound) {
			pendings, lErr := a.repo.ListPendingChallengesByIdentifier(
				ctx,
				input.Email,
				domain.VerificationPurposeEmailVerification,
			)
			if lErr == nil && len(pendings) > 0 {
				newest := pendings[0]
				return &RequestEmailVerificationOutput{Challenge: &newest}, nil
			}
		}

		slog.WarnContext(ctx, "user email not found for verification request", "error", err)
		return &RequestEmailVerificationOutput{}, nil
	}

	if emailRec.IsDeleted() || emailRec.IsVerified() {
		slog.WarnContext(ctx, "email verification requested for ineligible email")
		return &RequestEmailVerificationOutput{}, nil
	}

	challenge := domain.VerificationChallenge{
		ID:          a.uid.Generate(),
		UserID:      &emailRec.UserID,
		FlowID:      nil,
		Identifier:  input.Email,
		Purpose:     domain.VerificationPurposeEmailVerification,
		CodeHash:    codeHash,
		Attempts:    0,
		MaxAttempts: maxAttempts,
		IPAddress:   &input.Meta.IPAddress,
		ExpiresAt:   now.Add(ttl),
		CreatedAt:   now,
	}

	if err := a.repo.CreateVerificationChallenge(ctx, challenge); err != nil {
		slog.ErrorContext(ctx, "failed to create verification challenge", "error", err)
		return nil, goerror.NewServer(err)
	}

	a.sendEmailVerificationMock(challenge, rawCode)

	a.logSecurityEvent(
		&emailRec.UserID,
		domain.SecurityEventTypeEmailVerificationRequest,
		input.Meta,
		map[string]any{"email": input.Email, "challenge_id": challenge.ID},
	)

	return &RequestEmailVerificationOutput{Challenge: &challenge}, nil
}

// sendEmailVerificationMock is a placeholder for real mail delivery.
// It intentionally never logs or transmits the raw code.
func (a *Application) sendEmailVerificationMock(challenge domain.VerificationChallenge, rawCode string) {
	a.goroutine.Go(context.Background(), func(ctx context.Context) error {
		slog.InfoContext(ctx, "mock send email verification",
			"identifier", challenge.Identifier,
			"challenge_id", challenge.ID,
			"expires_at", challenge.ExpiresAt,
			"raw_code", rawCode,
		)

		return nil
	})
}

// generateEmailVerificationCode returns a zero-padded 6-digit numeric code.
func generateEmailVerificationCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%06d", n.Int64()), nil
}
