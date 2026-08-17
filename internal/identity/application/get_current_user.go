package application

import (
	"context"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

type GetCurrentUserInput struct{}

type GetCurrentUserOutput struct {
	User         domain.User
	Emails       []domain.UserEmail
	PhoneNumbers []domain.UserPhoneNumber
	Identities   []domain.Identity
}

func (a *Application) GetCurrentUser(ctx context.Context, input GetCurrentUserInput) (*GetCurrentUserOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "GetCurrentUser")
	defer span.End()

	claims := jwt.GetAuth(ctx)
	if claims == nil {
		return nil, goerror.NewBusiness("unauthenticated", goerror.CodeUnauthorized)
	}

	user, err := a.repo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	if user.IsDeleted() {
		return nil, goerror.NewBusiness("user is deleted", goerror.CodeNotFound)
	}

	emails, err := a.repo.ListUserEmailsByUserID(ctx, user.ID, false)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	phones, err := a.repo.ListPhonesByUserID(ctx, user.ID)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	identities, err := a.repo.ListIdentitiesByUserID(ctx, user.ID)
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	return &GetCurrentUserOutput{
		User:         user,
		Emails:       emails,
		PhoneNumbers: phones,
		Identities:   identities,
	}, nil
}
