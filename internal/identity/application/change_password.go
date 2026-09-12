package application

// import (
// 	"context"
// 	"errors"

// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/goerror"
// 	"github.com/qarven/oryon-go/internal/pkg/jwt"
// )

// type ChangePasswordInput struct {
// 	CurrentPassword string `validate:"required"`
// 	NewPassword     string `validate:"required,password"`
// }

// type ChangePasswordOutput struct{}

// func (a *Application) ChangePassword(ctx context.Context, input ChangePasswordInput) (*ChangePasswordOutput, error) {
// 	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "ChangePassword")
// 	defer span.End()

// 	if err := a.validator.Validate(input); err != nil {
// 		return nil, goerror.NewInvalidInput(err)
// 	}

// 	if input.CurrentPassword == input.NewPassword {
// 		return nil, goerror.NewBusiness("new password must be different", goerror.CodeInvalidInput)
// 	}

// 	claims := jwt.GetAuth(ctx)
// 	if claims == nil {
// 		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
// 	}

// 	userID := claims.UserID

// 	cred, err := a.repo.GetPasswordCredentialByUserID(ctx, userID)
// 	if err != nil {
// 		if errors.Is(err, domain.ErrPasswordCredentialNotFound) {
// 			return nil, goerror.NewBusiness("password credential not found", goerror.CodeNotFound)
// 		}

// 		return nil, goerror.NewServer(err)
// 	}

// 	if !a.argon2id.Verify(cred.Password, input.CurrentPassword) {
// 		return nil, goerror.NewBusiness("current password is incorrect", goerror.CodeUnauthorized)
// 	}

// 	newHash, err := a.argon2id.Hash(input.NewPassword)
// 	if err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	now := a.clock.Now()
// 	cred.Password = string(newHash)
// 	cred.PasswordChangedAt = now
// 	cred.UpdatedAt = now

// 	if err := a.repo.UpdatePasswordCredential(ctx, cred); err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	a.logSecurityEvent(ctx, &userID, "password.changed", nil, nil, map[string]any{})

// 	return &ChangePasswordOutput{}, nil
// }
