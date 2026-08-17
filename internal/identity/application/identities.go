package application

import (
	"context"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/paginate"
)

type IdentitiesInput struct {
	Email string
	Name  string
	Limit int32
	Page  int32
}

type IdentitiesOutput struct {
	Identities []domain.Identity
	Total      int64
}

func (a *Application) Identities(ctx context.Context, input IdentitiesInput) (*IdentitiesOutput, error) {
	ctx, span := a.ins.Tracer("identity.application").Start(ctx, "Identities")
	defer span.End()

	limit, offset := paginate.Normalize(input.Limit, input.Page)

	identities, total, err := a.repo.ListIdentities(ctx, domain.ListIdentitiesArgument{
		Email:  input.Email,
		Name:   input.Name,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, goerror.NewServer(err)
	}

	return &IdentitiesOutput{
		Identities: identities,
		Total:      total,
	}, nil
}
