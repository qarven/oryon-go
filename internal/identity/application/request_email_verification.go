package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

type RequestEmailVerificationInput struct {
	Email   *string `validate:"omitempty,email"`
	EmailID *int64  `validate:"omitempty"`
}

type RequestEmailVerificationOutput struct {
	Challenge domain.VerificationChallenge
}

func (a *Application) RequestEmailVerification(ctx context.Context, input RequestEmailVerificationInput) (*RequestEmailVerificationOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "RequestEmailVerification")
	defer span.End()

	claims := jwt.GetAuth(ctx)
	if claims == nil {
		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
	}

	userID := claims.UserID

	var targetEmail string
	var targetEmailID int64

	if input.EmailID != nil {
		e, err := a.repo.GetUserEmailByID(ctx, *input.EmailID)
		if err != nil {
			if errors.Is(err, domain.ErrEmailNotFound) {
				return nil, goerror.NewBusiness("email not found", goerror.CodeNotFound)
			}

			return nil, goerror.NewServer(err)
		}

		if e.UserID != userID {
			return nil, goerror.NewBusiness("email does not belong to user", goerror.CodeForbidden)
		}

		targetEmail = e.Email
		targetEmailID = e.ID
	} else if input.Email != nil && *input.Email != "" {
		// find email by string for this user
		emails, err := a.repo.ListUserEmailsByUserID(ctx, userID, false)
		if err != nil {
			return nil, goerror.NewServer(err)
		}

		found := false
		for _, e := range emails {
			if e.Email == *input.Email {
				targetEmail = e.Email
				targetEmailID = e.ID
				found = true
				break
			}
		}

		if !found {
			return nil, goerror.NewBusiness("email not found", goerror.CodeNotFound)
		}
	} else {
		// use primary
		pe, err := a.repo.GetPrimaryUserEmailByUserID(ctx, userID)
		if err != nil {
			return nil, goerror.NewServer(err)
		}

		targetEmail = pe.Email
		targetEmailID = pe.ID
	}

	// Rate limit via cache
	if ok, _ := a.cache.CheckVerificationRateLimit(ctx, targetEmail); !ok {
		return nil, goerror.NewBusiness("too many verification requests", goerror.CodeTooManyRequest)
	}

	now := a.clock.Now()
	// Generate 6-digit OTP
	raw := make([]byte, 3)
	if _, err := rand.Read(raw); err != nil {
		return nil, goerror.NewServer(err)
	}

	num := int(raw[0])<<16 | int(raw[1])<<8 | int(raw[2])
	code := hex.EncodeToString([]byte{byte(num % 1000000)}) // placeholder, use numeric
	// Generate numeric OTP properly: 6 digits
	codeNum := num % 1000000
	code = hex.EncodeToString([]byte{}) // will replace
	_ = code
	code = formatOTP(codeNum, 6)

	hash := sha256.Sum256([]byte(code))
	chID := a.uid.Generate()
	expires := now.Add(10 * time.Minute)

	vc, err := domain.NewVerificationChallenge(chID, &userID, nil, targetEmail, domain.VerificationPurposeEmailVerification, hash[:], 3, nil, now, expires)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	if err := a.repo.CreateVerificationChallenge(ctx, *vc); err != nil {
		return nil, goerror.NewServer(err)
	}

	_ = a.cache.IncrementVerificationAttempt(ctx, targetEmail)

	// Send email async (mock)
	a.goroutine.Go(context.Background(), func(ctx context.Context) error {
		_ = targetEmailID
		_ = code
		return nil
	})

	a.logSecurityEvent(ctx, &userID, "email.verification_requested", nil, nil, map[string]any{"email": targetEmail, "challenge_id": chID})

	return &RequestEmailVerificationOutput{Challenge: *vc}, nil
}

func formatOTP(num int, digits int) string {
	s := make([]byte, digits)
	for i := digits - 1; i >= 0; i-- {
		s[i] = byte('0' + num%10)
		num /= 10
	}

	return string(s)
}
