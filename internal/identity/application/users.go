package application

import (
	"context"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/paginate"
)

type UsersInput struct {
	Email string
	Name  string
	Limit int32
	Page  int32
}

type UsersOutput struct {
	Users []domain.User
	Total int64
}

func (a *Application) Users(ctx context.Context, input UsersInput) (*UsersOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "Users")
	defer span.End()

	limit, offset := paginate.Normalize(input.Limit, input.Page)

	users, total, err := a.repo.ListUsers(ctx, domain.ListUsersArgument{
		Email:  input.Email,
		Name:   input.Name,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	return &UsersOutput{
		Users: users,
		Total: total,
	}, nil
}
