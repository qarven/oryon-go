package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

type VerifyEmailInput struct {
	Token          string  `validate:"required"`
	Code           *string `validate:"omitempty"`
	VerificationID *string `validate:"omitempty"`
	Email          *string `validate:"omitempty,email"`
}

type VerifyEmailOutput struct {
	Email    domain.UserEmail
	Verified bool
}

func (a *Application) VerifyEmail(ctx context.Context, input VerifyEmailInput) (*VerifyEmailOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "VerifyEmail")
	defer span.End()

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	var vc domain.VerificationChallenge
	var err error

	now := a.clock.Now()

	if input.VerificationID != nil && *input.VerificationID != "" {
		vid, perr := strconv.ParseInt(*input.VerificationID, 10, 64)
		if perr != nil {
			return nil, goerror.NewBusiness("invalid verification_id", goerror.CodeInvalidInput)
		}

		ch, gerr := a.repo.GetVerificationChallengeByID(ctx, vid)
		if gerr != nil {
			return nil, goerror.NewBusiness("verification not found", goerror.CodeNotFound)
		}

		vc = ch
		codeToVerify := input.Code
		if codeToVerify == nil {
			codeToVerify = &input.Token
		}

		hash := sha256.Sum256([]byte(*codeToVerify))
		if string(vc.CodeHash) != string(hash[:]) && hex.EncodeToString(vc.CodeHash) != hex.EncodeToString(hash[:]) {
			vc.IncrementAttempts()
			_ = a.repo.UpdateVerificationChallenge(ctx, vc)
			return nil, goerror.NewBusiness("invalid verification code", goerror.CodeUnauthorized)
		}
	} else {
		// Token is raw OTP
		raw := input.Token
		if input.Code != nil && *input.Code != "" {
			raw = *input.Code
		}

		hash := sha256.Sum256([]byte(raw))
		ch, gerr := a.repo.GetVerificationChallengeByHash(ctx, hash[:], domain.VerificationPurposeEmailVerification)
		if gerr != nil {
			// Try identifier email search fallback
			var emailIdent string
			if input.Email != nil {
				emailIdent = *input.Email
			} else {
				claims := jwt.GetAuth(ctx)
				if claims != nil {
					if pe, err := a.repo.GetPrimaryUserEmailByUserID(ctx, claims.UserID); err == nil {
						emailIdent = pe.Email
					}
				}
			}

			if emailIdent != "" {
				challs, err2 := a.repo.GetVerificationByIdentifierPurpose(ctx, emailIdent, domain.VerificationPurposeEmailVerification)
				if err2 == nil {
					for _, c := range challs {
						if string(c.CodeHash) == string(hash[:]) || hex.EncodeToString(c.CodeHash) == hex.EncodeToString(hash[:]) {
							ch = c
							gerr = nil
							break
						}
					}
				}
			}

			if gerr != nil {
				return nil, goerror.NewBusiness("invalid or expired verification token", goerror.CodeInvalidInput)
			}
		}

		vc = ch
	}

	if err := vc.CanAttempt(now); err != nil {
		if errors.Is(err, domain.ErrVerificationExpired) {
			return nil, goerror.NewBusiness("verification expired", goerror.CodeInvalidInput)
		}

		if errors.Is(err, domain.ErrVerificationConsumed) {
			return nil, goerror.NewBusiness("verification already consumed", goerror.CodeInvalidInput)
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

	// Mark email verified
	emailStr := vc.Identifier
	if input.Email != nil && *input.Email != "" {
		emailStr = *input.Email
	}

	emailRec, err := a.repo.GetUserEmailByEmail(ctx, emailStr)
	if err != nil {
		// try by identifier
		emails, _ := a.repo.GetVerificationByIdentifierPurpose(ctx, vc.Identifier, domain.VerificationPurposeEmailVerification)
		_ = emails
		return nil, goerror.NewBusiness("email not found", goerror.CodeNotFound)
	}

	emailRec.MarkVerified(now)
	if err := a.repo.UpdateUserEmail(ctx, emailRec); err != nil {
		return nil, goerror.NewServer(err)
	}

	var uid *int64
	if vc.UserID != nil {
		uid = vc.UserID
	} else {
		uid = &emailRec.UserID
	}

	a.logSecurityEvent(ctx, uid, "email.verified", nil, nil, map[string]any{"email": emailRec.Email})

	return &VerifyEmailOutput{Email: emailRec, Verified: true}, nil
}
