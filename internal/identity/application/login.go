package application

import (
	"context"
	"errors"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
)

type LoginInput struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required,password"`
}

type LoginOutput struct {
	AccessToken  string
	RefreshToken string
}

func (a *Application) Login(ctx context.Context, input LoginInput) (*LoginOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "Login")
	defer span.End()

	err := a.validator.Validate(input)
	if err != nil {
		return nil, goerror.NewInvalidInput(err)
	}

	user, err := a.repo.GetUserByEmail(ctx, input.Email)
	if errors.Is(err, domain.ErrUserNotFound) {
		return nil, goerror.NewBusiness("invalid email or password", goerror.CodeUnauthorized)
	}

	if err != nil {
		return nil, goerror.NewServer(err)
	}

	if user.Status != domain.UserStatusActive {
		return nil, goerror.NewBusiness("account is disabled", goerror.CodeForbidden)
	}

	credential, err := a.repo.GetCredentialByUserID(ctx, user.ID, domain.CredentialTypePassword)
	if errors.Is(err, domain.ErrCredentialNotFound) {
		return nil, goerror.NewBusiness("invalid email or password", goerror.CodeUnauthorized)
	}

	if err != nil {
		return nil, goerror.NewServer(err)
	}

	if credential.PasswordHash == nil || !a.argon2id.Verify(*credential.PasswordHash, input.Password) {
		return nil, goerror.NewBusiness("invalid email or password", goerror.CodeUnauthorized)
	}

	accessToken, refreshToken, err := a.issueTokens(user.ID, user.Email)
	if err != nil {
		return nil, err
	}

	return &LoginOutput{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
