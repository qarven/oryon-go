package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func toIdentity(id int64, email, name string, status int16) *domain.Identity {
	return &domain.Identity{
		ID:     id,
		Email:  email,
		Name:   name,
		Status: domain.IdentityStatus(status),
	}
}

func (p *Postgres) GetIdentityByEmail(ctx context.Context, email string) (*domain.Identity, error) {
	ctx, span := p.ins.Tracer("identity.infrastructure.persistence").Start(ctx, "GetIdentityByEmail")
	defer span.End()

	row, err := p.query.GetIdentityByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrIdentityNotFound
	}

	if err != nil {
		return nil, err
	}

	return toIdentity(row.ID, row.Email, row.Name, row.Status), nil
}

func (p *Postgres) ListIdentities(ctx context.Context, arg domain.ListIdentitiesArgument) ([]domain.Identity, int64, error) {
	ctx, span := p.ins.Tracer("identity.infrastructure.persistence").Start(ctx, "ListIdentities")
	defer span.End()

	rows, err := p.query.ListIdentities(ctx, sqlc.ListIdentitiesParams{
		Email:      pgtype.Text{String: arg.Email, Valid: arg.Email != ""},
		Name:       pgtype.Text{String: arg.Name, Valid: arg.Name != ""},
		OffsetRows: arg.Offset,
		LimitRows:  arg.Limit,
	})
	if err != nil {
		return nil, 0, err
	}

	identities := make([]domain.Identity, 0, len(rows))
	for _, row := range rows {
		identities = append(identities, *toIdentity(row.ID, row.Email, row.Name, row.Status))
	}

	total := int64(0)
	if len(rows) > 0 {
		total = rows[0].TotalCount
	}

	return identities, total, nil
}

func (p *Postgres) GetIdentityByID(ctx context.Context, id int64) (*domain.Identity, error) {
	ctx, span := p.ins.Tracer("identity.infrastructure.persistence").Start(ctx, "GetIdentityByID")
	defer span.End()

	row, err := p.query.GetIdentityByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrIdentityNotFound
	}

	if err != nil {
		return nil, err
	}

	return toIdentity(row.ID, row.Email, row.Name, row.Status), nil
}
