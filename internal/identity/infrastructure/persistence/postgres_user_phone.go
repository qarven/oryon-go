package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) CreateUserPhoneNumber(ctx context.Context, ph domain.UserPhoneNumber) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateUserPhoneNumber")
	defer span.End()

	return p.query.CreateUserPhoneNumber(ctx, sqlc.CreateUserPhoneNumberParams{
		ID:         ph.ID,
		UserID:     ph.UserID,
		Phone:      ph.Phone,
		CreatedAt:  pgTimestamptz(ph.CreatedAt),
		VerifiedAt: pgTimestamptzPtr(ph.VerifiedAt),
		DeletedAt:  pgTimestamptzPtr(ph.DeletedAt),
	})
}

func (p *Postgres) GetUserPhoneByPhone(ctx context.Context, phone string) (domain.UserPhoneNumber, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetUserPhoneByPhone")
	defer span.End()

	row, err := p.query.GetUserPhoneByPhone(ctx, phone)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.UserPhoneNumber{}, domain.ErrPhoneNotFound
		}
		return domain.UserPhoneNumber{}, err
	}
	return domain.UserPhoneNumber{
		ID:         row.ID,
		UserID:     row.UserID,
		Phone:      row.Phone,
		CreatedAt:  row.CreatedAt.Time,
		VerifiedAt: fromPgTimestamptz(row.VerifiedAt),
		DeletedAt:  fromPgTimestamptz(row.DeletedAt),
	}, nil
}

func (p *Postgres) ListPhonesByUserID(ctx context.Context, userID int64) ([]domain.UserPhoneNumber, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ListPhonesByUserID")
	defer span.End()

	rows, err := p.query.ListPhonesByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.UserPhoneNumber, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.UserPhoneNumber{
			ID:         r.ID,
			UserID:     r.UserID,
			Phone:      r.Phone,
			CreatedAt:  r.CreatedAt.Time,
			VerifiedAt: fromPgTimestamptz(r.VerifiedAt),
			DeletedAt:  fromPgTimestamptz(r.DeletedAt),
		})
	}
	return out, nil
}

func (p *Postgres) GetUserPhoneByID(ctx context.Context, id int64) (domain.UserPhoneNumber, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetUserPhoneByID")
	defer span.End()

	row, err := p.query.GetUserPhoneByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.UserPhoneNumber{}, domain.ErrPhoneNotFound
		}
		return domain.UserPhoneNumber{}, err
	}
	return domain.UserPhoneNumber{
		ID:         row.ID,
		UserID:     row.UserID,
		Phone:      row.Phone,
		CreatedAt:  row.CreatedAt.Time,
		VerifiedAt: fromPgTimestamptz(row.VerifiedAt),
		DeletedAt:  fromPgTimestamptz(row.DeletedAt),
	}, nil
}
