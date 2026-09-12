package application

// import (
// 	"context"
// 	"errors"

// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/goerror"
// 	"github.com/qarven/oryon-go/internal/pkg/jwt"
// )

// type SetPrimaryEmailInput struct {
// 	EmailID int64 `validate:"required,gt=0"`
// }

// type SetPrimaryEmailOutput struct {
// 	Email domain.UserEmail
// }

// func (a *Application) SetPrimaryEmail(ctx context.Context, input SetPrimaryEmailInput) (*SetPrimaryEmailOutput, error) {
// 	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "SetPrimaryEmail")
// 	defer span.End()

// 	if err := a.validator.Validate(input); err != nil {
// 		return nil, goerror.NewInvalidInput(err)
// 	}

// 	claims := jwt.GetAuth(ctx)
// 	if claims == nil {
// 		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
// 	}

// 	email, err := a.repo.GetUserEmailByID(ctx, input.EmailID)
// 	if err != nil {
// 		if errors.Is(err, domain.ErrEmailNotFound) {
// 			return nil, goerror.NewBusiness("email not found", goerror.CodeNotFound)
// 		}

// 		return nil, goerror.NewServer(err)
// 	}

// 	if email.UserID != claims.UserID {
// 		return nil, goerror.NewBusiness("email does not belong to user", goerror.CodeForbidden)
// 	}

// 	if email.IsDeleted() {
// 		return nil, goerror.NewBusiness("email is deleted", goerror.CodeInvalidInput)
// 	}

// 	if !email.IsVerified() {
// 		return nil, goerror.NewBusiness("email must be verified to be set as primary", goerror.CodeInvalidInput)
// 	}

// 	if email.IsPrimary {
// 		return &SetPrimaryEmailOutput{Email: email}, nil
// 	}

// 	if err := a.repo.SetPrimaryEmailTx(ctx, claims.UserID, email.ID); err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	// refetch
// 	updated, err := a.repo.GetUserEmailByID(ctx, email.ID)
// 	if err != nil {
// 		return nil, goerror.NewServer(err)
// 	}

// 	a.logSecurityEvent(ctx, &claims.UserID, "email.set_primary", nil, map[string]any{"email": updated.Email})

// 	return &SetPrimaryEmailOutput{Email: updated}, nil
// }
