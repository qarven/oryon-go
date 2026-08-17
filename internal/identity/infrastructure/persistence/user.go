package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func toUser(id int64, email, name string, status int16) *domain.User {
	return &domain.User{
		ID:     id,
		Email:  email,
		Name:   name,
		Status: domain.UserStatus(status),
	}
}

func (p *Postgres) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	ctx, span := p.ins.Tracer("identity.infrastructure.persistence").Start(ctx, "GetUserByEmail")
	defer span.End()

	row, err := p.query.GetUserByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}

	if err != nil {
		return nil, err
	}

	return toUser(row.ID, row.Email, row.Name, row.Status), nil
}

func (p *Postgres) ListUsers(ctx context.Context, arg domain.ListUsersArgument) ([]domain.User, int64, error) {
	ctx, span := p.ins.Tracer("identity.infrastructure.persistence").Start(ctx, "ListUsers")
	defer span.End()

	rows, err := p.query.ListUsers(ctx, sqlc.ListUsersParams{
		Email:      pgtype.Text{String: arg.Email, Valid: arg.Email != ""},
		Name:       pgtype.Text{String: arg.Name, Valid: arg.Name != ""},
		OffsetRows: arg.Offset,
		LimitRows:  arg.Limit,
	})
	if err != nil {
		return nil, 0, err
	}

	users := make([]domain.User, 0, len(rows))
	for _, row := range rows {
		users = append(users, *toUser(row.ID, row.Email, row.Name, row.Status))
	}

	total := int64(0)
	if len(rows) > 0 {
		total = rows[0].TotalCount
	}

	return users, total, nil
}

func (p *Postgres) GetUserByID(ctx context.Context, id int64) (*domain.User, error) {
	ctx, span := p.ins.Tracer("identity.infrastructure.persistence").Start(ctx, "GetUserByID")
	defer span.End()

	row, err := p.query.GetUserByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}

	if err != nil {
		return nil, err
	}

	return toUser(row.ID, row.Email, row.Name, row.Status), nil
}
