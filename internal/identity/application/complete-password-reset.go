package application

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type CompletePasswordResetInput struct {
	Code        string    `validate:"required"`
	NewPassword string    `validate:"required,password"`
	Meta        MetaInput `validate:"required"`
}

type CompletePasswordResetOutput struct {
	User *domain.User
}

// CompletePasswordResetData carries the atomic password update.
type CompletePasswordResetData struct {
	UserID    domain.ID
	Password  string
	ChangedAt time.Time
	UpdatedAt time.Time
	Challenge domain.VerificationChallenge
}

func (a *Application) CompletePasswordReset(
	ctx context.Context,
	input CompletePasswordResetInput,
) (*CompletePasswordResetOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "CompletePasswordReset")
	defer span.End()

	input.Code = strings.TrimSpace(input.Code)

	err := a.validator.Validate(input)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	now := a.clock.Now()

	verificationID, rawSecret, err := a.parsePasswordResetCode(input.Code)
	if err != nil {
		slog.WarnContext(ctx, "invalid password reset code format")

		return nil, err
	}

	challenge, err := a.loadPasswordResetChallenge(ctx, verificationID, now, rawSecret)
	if err != nil {
		return nil, err
	}

	user, err := a.repo.GetUserByID(ctx, *challenge.UserID)
	if errors.Is(err, domain.ErrUserNotFound) {
		slog.WarnContext(ctx, "password reset user not found",
			"verification_id", challenge.ID,
			"user_id", *challenge.UserID,
		)

		return nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeInvalidInput)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "user_id", *challenge.UserID, "error", err)

		return nil, goerror.NewServer(err)
	}

	if user.IsDeleted() {
		slog.WarnContext(ctx, "password reset user is deleted", "verification_id", challenge.ID)

		return nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeInvalidInput)
	}

	err = challenge.CanAttempt(now)
	if err != nil {
		slog.WarnContext(ctx, "password reset challenge cannot be attempted",
			"verification_id", challenge.ID,
			"error", err,
		)

		if errors.Is(err, domain.ErrVerificationAttemptsExceeded) {
			return nil, goerror.NewBusiness("too many attempts", goerror.CodeTooManyRequest)
		}

		return nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeInvalidInput)
	}

	hash, err := a.argon2id.Hash(input.NewPassword)
	if err != nil {
		slog.ErrorContext(ctx, "failed to hash new password", "error", err)

		return nil, goerror.NewServer(err)
	}

	challenge.ConsumedAt = &now

	err = a.repo.CompletePasswordReset(ctx, CompletePasswordResetData{
		UserID:    user.ID,
		Password:  string(hash),
		ChangedAt: now,
		UpdatedAt: now,
		Challenge: *challenge,
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to complete password reset",
			"user_id", user.ID,
			"verification_id", challenge.ID,
			"error", err,
		)

		return nil, goerror.NewServer(err)
	}

	a.securityEvent(domain.SecurityEventTypePasswordResetCompleted).
		ForUser(&user.ID).
		WithMeta(input.Meta).
		With("verification_id", challenge.ID).
		Emit(ctx)

	return &CompletePasswordResetOutput{User: user}, nil
}

func (a *Application) parsePasswordResetCode(code string) (domain.ID, string, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		return "", "", goerror.NewBusiness("invalid or expired verification", goerror.CodeInvalidInput)
	}

	verificationID, rawSecret, found := strings.Cut(string(bytes), "-")
	if !found {
		return "", "", goerror.NewBusiness("invalid or expired verification", goerror.CodeInvalidInput)
	}

	verificationID = strings.TrimSpace(verificationID)
	rawSecret = strings.TrimSpace(rawSecret)

	if len(verificationID) != 32 || len(rawSecret) != 32 {
		return "", "", goerror.NewBusiness("invalid or expired verification", goerror.CodeInvalidInput)
	}

	verID, err := domain.IDParse(verificationID)
	if err != nil {
		return "", "", goerror.NewBusiness("invalid or expired verification", goerror.CodeInvalidInput)
	}

	return verID, rawSecret, nil
}

func (a *Application) loadPasswordResetChallenge(
	ctx context.Context,
	verificationID domain.ID,
	now time.Time,
	rawSecret string,
) (*domain.VerificationChallenge, error) {
	challenge, err := a.repo.GetVerificationChallengeByID(ctx, verificationID)
	if errors.Is(err, domain.ErrVerificationNotFound) {
		slog.WarnContext(ctx, "password reset challenge not found", "verification_id", verificationID)

		return nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeInvalidInput)
	}

	if err != nil {
		slog.ErrorContext(ctx, "failed to get verification challenge",
			"verification_id", verificationID,
			"error", err,
		)

		return nil, goerror.NewServer(err)
	}

	if challenge.Purpose != domain.VerificationPurposePasswordReset {
		slog.WarnContext(ctx, "password reset challenge purpose mismatch",
			"verification_id", verificationID,
			"purpose", challenge.Purpose,
		)

		return nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeInvalidInput)
	}

	if challenge.UserID == nil {
		slog.WarnContext(ctx, "password reset challenge has no user",
			"verification_id", verificationID,
			"challenge_id", challenge.ID,
		)

		return nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeInvalidInput)
	}

	err = challenge.CanAttempt(now)
	if err != nil {
		slog.WarnContext(ctx, "password reset challenge cannot be attempted",
			"verification_id", verificationID,
			"error", err,
		)

		if errors.Is(err, domain.ErrVerificationAttemptsExceeded) {
			return nil, goerror.NewBusiness("too many attempts", goerror.CodeTooManyRequest)
		}

		return nil, goerror.NewBusiness("invalid or expired verification", goerror.CodeInvalidInput)
	}

	if !a.sha256.Verify(string(challenge.CodeHash), rawSecret) {
		challenge.Attempts++

		err := a.repo.UpdateVerificationChallenge(ctx, *challenge)
		if err != nil {
			slog.ErrorContext(ctx, "failed to update verification challenge attempts",
				"verification_id", challenge.ID,
				"error", err,
			)

			return nil, goerror.NewServer(err)
		}

		slog.WarnContext(ctx, "invalid password reset code", "verification_id", challenge.ID)

		return nil, goerror.NewBusiness("invalid verification code", goerror.CodeUnauthorized)
	}

	return challenge, nil
}
