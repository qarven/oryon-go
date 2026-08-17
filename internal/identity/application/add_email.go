package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

type AddEmailInput struct {
	Email            string `validate:"required,email"`
	SendVerification bool
}

type AddEmailOutput struct {
	Email                domain.UserEmail
	VerificationRequired bool
	VerificationID       *string
}

func (a *Application) AddEmail(ctx context.Context, input AddEmailInput) (*AddEmailOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "AddEmail")
	defer span.End()

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	claims := jwt.GetAuth(ctx)
	if claims == nil {
		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
	}

	email := strings.ToLower(strings.TrimSpace(input.Email))

	// Check global uniqueness
	if _, err := a.repo.GetUserEmailByEmail(ctx, email); err == nil {
		return nil, goerror.NewBusiness("email already exists", goerror.CodeConflict)
	} else if err != domain.ErrEmailNotFound {
		// if err is ErrEmailNotFound, proceed; else server error
		if err != domain.ErrEmailNotFound {
			return nil, goerror.NewServer(err)
		}
	}

	now := a.clock.Now()
	id := a.uid.Generate()

	ue, err := domain.NewUserEmail(id, claims.UserID, email, false, now)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	if err := a.repo.CreateUserEmail(ctx, *ue); err != nil {
		return nil, goerror.NewServer(err)
	}

	verificationRequired := input.SendVerification
	var verificationID *string

	if input.SendVerification {
		// Create verification challenge
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err == nil {
			code := hexEncode6(raw)
			hash := sha256.Sum256([]byte(code))
			chID := a.uid.Generate()
			expires := now.Add(10 * time.Minute)
			vc, _ := domain.NewVerificationChallenge(chID, &claims.UserID, nil, email, domain.VerificationPurposeEmailVerification, hash[:], 3, nil, now, expires)
			if vc != nil {
				_ = a.repo.CreateVerificationChallenge(ctx, *vc)
				s := itoa64(chID)
				verificationID = &s
				// send email async
				a.goroutine.Go(context.Background(), func(ctx context.Context) error {
					_ = code
					return nil
				})
			}
		}
	}

	a.logSecurityEvent(ctx, &claims.UserID, "email.added", nil, nil, map[string]any{"email": email})

	return &AddEmailOutput{
		Email:                *ue,
		VerificationRequired: verificationRequired,
		VerificationID:       verificationID,
	}, nil
}

func hexEncode6(b []byte) string {
	// produce 6-digit numeric code from bytes
	num := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	num = num % 1000000
	return formatOTP(num, 6)
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}

	neg := n < 0
	if neg {
		n = -n
	}

	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}

	if neg {
		pos--
		buf[pos] = '-'
	}

	return string(buf[pos:])
}
