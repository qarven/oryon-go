package application

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

var rePhone = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

type RegistrationInput struct {
	Email    *string `validate:"required,email"`
	Phone    *string `validate:"omitempty,e164"`
	Password string  `validate:"required,password"`
	Name     string  `validate:"required,min=1"`
}

type RegistrationOutput struct {
	User                 domain.User
	Flow                 *domain.AuthFlow
	VerificationRequired bool
}

func (a *Application) Registration(ctx context.Context, input RegistrationInput) (*RegistrationOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "Registration")
	defer span.End()

	if err := a.validator.Validate(input); err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	if input.Phone != nil && *input.Phone != "" {
		if !rePhone.MatchString(*input.Phone) {
			return nil, goerror.NewInvalidInput(nil, "phone", "phone must be E.164 format")
		}
	}

	email := strings.ToLower(strings.TrimSpace(*input.Email))

	// Check email uniqueness
	_, err := a.repo.GetUserEmailByEmail(ctx, email)
	if err == nil {
		return nil, goerror.NewBusiness("email already registered", goerror.CodeConflict)
	}

	if err != domain.ErrEmailNotFound {
		return nil, goerror.NewServer(err)
	}

	now := a.clock.Now()
	userID := a.uid.Generate()

	user, err := domain.NewUser(userID, input.Name, nil, now)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	if err := a.repo.CreateUser(ctx, *user); err != nil {
		return nil, goerror.NewServer(err)
	}

	// Create primary email
	emailID := a.uid.Generate()
	userEmail, err := domain.NewUserEmail(emailID, userID, email, true, now)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	if err := a.repo.CreateUserEmail(ctx, *userEmail); err != nil {
		return nil, goerror.NewServer(err)
	}

	// Phone optional
	if input.Phone != nil && *input.Phone != "" {
		phoneID := a.uid.Generate()
		ph, err := domain.NewUserPhoneNumber(phoneID, userID, *input.Phone, now)
		if err == nil {
			_ = a.repo.CreateUserPhoneNumber(ctx, *ph)
		}
	}

	// Password credential
	hash, err := a.argon2id.Hash(input.Password)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	cred, _ := domain.NewPasswordCredential(userID, string(hash), now)
	if err := a.repo.CreatePasswordCredential(ctx, *cred); err != nil {
		return nil, goerror.NewServer(err)
	}

	// Optionally create phone if needed: already done

	var flow *domain.AuthFlow

	flowID := a.uid.Generate()
	expires := now.Add(15 * time.Minute)
	f, _ := domain.NewAuthFlow(flowID, &userID, domain.AuthFlowTypeRegistration, domain.AuthFlowStatePendingVerification, nil, nil, map[string]any{"email": email}, now, expires)
	if f != nil {
		_ = a.repo.CreateAuthFlow(ctx, *f)
		flow = f
	}

	return &RegistrationOutput{
		User:                 *user,
		Flow:                 flow,
		VerificationRequired: true,
	}, nil
}
