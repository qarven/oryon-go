package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type ConfirmPasswordResetInput struct {
	Token       string  `validate:"required"`
	Code        *string `validate:"omitempty"`
	NewPassword string  `validate:"required,password"`
	IPAddress   *string
	UserAgent   *string
}

type ConfirmPasswordResetOutput struct {
	Token        *string
	RefreshToken *string
}

func (a *Application) ConfirmPasswordReset(ctx context.Context, input ConfirmPasswordResetInput) (*ConfirmPasswordResetOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "ConfirmPasswordReset")
	defer span.End()

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	var vc domain.VerificationChallenge
	var err error
	now := a.clock.Now()

	// If Code is provided, Token is verification_id (decimal)
	if input.Code != nil && *input.Code != "" {
		vid, perr := strconv.ParseInt(input.Token, 10, 64)
		if perr != nil {
			return nil, goerror.NewBusiness("invalid verification id", goerror.CodeInvalidInput)
		}

		ch, gerr := a.repo.GetVerificationChallengeByID(ctx, vid)
		if gerr != nil {
			if errors.Is(gerr, domain.ErrVerificationNotFound) {
				return nil, goerror.NewBusiness("verification challenge not found", goerror.CodeNotFound)
			}

			return nil, goerror.NewServer(gerr)
		}

		vc = ch
		// verify code
		codeHash := sha256.Sum256([]byte(*input.Code))
		if string(vc.CodeHash) != string(codeHash[:]) {
			// also compare hex representation in case stored as hex
			if hex.EncodeToString(vc.CodeHash) != hex.EncodeToString(codeHash[:]) {
				vc.IncrementAttempts()
				_ = a.repo.UpdateVerificationChallenge(ctx, vc)
				return nil, goerror.NewBusiness("invalid code", goerror.CodeUnauthorized)
			}
		}
	} else {
		// Token is raw token (hex or plain)
		raw := input.Token
		h := sha256.Sum256([]byte(raw))
		hashBytes := h[:]
		ch, gerr := a.repo.GetVerificationChallengeByHash(ctx, hashBytes, domain.VerificationPurposePasswordReset)
		if gerr != nil {
			// try with hex decoding fallback? In case token was originally hex-encoded then hashed as raw hex string, same
			// also try direct token string as identifier search fallback
			if errors.Is(gerr, domain.ErrVerificationNotFound) {
				return nil, goerror.NewBusiness("invalid or expired reset token", goerror.CodeInvalidInput)
			}

			return nil, goerror.NewServer(gerr)
		}

		vc = ch
	}

	if err := vc.CanAttempt(now); err != nil {
		if errors.Is(err, domain.ErrVerificationExpired) {
			return nil, goerror.NewBusiness("reset token expired", goerror.CodeInvalidInput)
		}

		if errors.Is(err, domain.ErrVerificationConsumed) {
			return nil, goerror.NewBusiness("reset token already used", goerror.CodeInvalidInput)
		}

		if errors.Is(err, domain.ErrVerificationAttemptsExceeded) {
			return nil, goerror.NewBusiness("too many attempts", goerror.CodeTooManyRequest)
		}

		return nil, goerror.NewBusiness(err.Error(), goerror.CodeInvalidInput)
	}

	if err := vc.Consume(now); err != nil {
		return nil, goerror.NewBusiness(err.Error(), goerror.CodeInvalidInput)
	}

	_ = a.repo.UpdateVerificationChallenge(ctx, vc)

	var userID int64
	if vc.UserID != nil {
		userID = *vc.UserID
	} else {
		emailRec, err := a.repo.GetUserEmailByEmail(ctx, vc.Identifier)
		if err != nil {
			return nil, goerror.NewBusiness("user not found", goerror.CodeNotFound)
		}

		userID = emailRec.UserID
	}

	cred, err := a.repo.GetPasswordCredentialByUserID(ctx, userID)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	newHash, err := a.argon2id.Hash(input.NewPassword)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	cred.Password = string(newHash)
	cred.PasswordChangedAt = now
	cred.UpdatedAt = now

	if err := a.repo.UpdatePasswordCredential(ctx, cred); err != nil {
		return nil, goerror.NewServer(err)
	}

	a.logSecurityEvent(ctx, &userID, "password.reset_completed", vc.IPAddress, nil, map[string]any{"challenge_id": vc.ID})

	_ = err
	return &ConfirmPasswordResetOutput{}, nil
}
