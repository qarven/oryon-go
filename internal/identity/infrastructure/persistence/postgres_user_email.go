package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) CreateUserEmail(ctx context.Context, email domain.UserEmail) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateUserEmail")
	defer span.End()

	return p.query.CreateUserEmail(ctx, sqlc.CreateUserEmailParams{
		ID:         email.ID,
		UserID:     email.UserID,
		Email:      email.Email,
		IsPrimary:  email.IsPrimary,
		CreatedAt:  pgTimestamptz(email.CreatedAt),
		VerifiedAt: pgTimestamptzPtr(email.VerifiedAt),
		DeletedAt:  pgTimestamptzPtr(email.DeletedAt),
	})
}

func (p *Postgres) GetUserEmailByID(ctx context.Context, id int64) (domain.UserEmail, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetUserEmailByID")
	defer span.End()

	row, err := p.query.GetUserEmailByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.UserEmail{}, domain.ErrEmailNotFound
		}
		return domain.UserEmail{}, err
	}
	return domain.UserEmail{
		ID:         row.ID,
		UserID:     row.UserID,
		Email:      row.Email,
		IsPrimary:  row.IsPrimary,
		CreatedAt:  row.CreatedAt.Time,
		VerifiedAt: fromPgTimestamptz(row.VerifiedAt),
		DeletedAt:  fromPgTimestamptz(row.DeletedAt),
	}, nil
}

func (p *Postgres) GetUserEmailByEmail(ctx context.Context, email string) (domain.UserEmail, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetUserEmailByEmail")
	defer span.End()

	row, err := p.query.GetUserEmailByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.UserEmail{}, domain.ErrEmailNotFound
		}
		return domain.UserEmail{}, err
	}
	return domain.UserEmail{
		ID:         row.ID,
		UserID:     row.UserID,
		Email:      row.Email,
		IsPrimary:  row.IsPrimary,
		CreatedAt:  row.CreatedAt.Time,
		VerifiedAt: fromPgTimestamptz(row.VerifiedAt),
		DeletedAt:  fromPgTimestamptz(row.DeletedAt),
	}, nil
}

func (p *Postgres) GetPrimaryUserEmailByUserID(ctx context.Context, userID int64) (domain.UserEmail, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetPrimaryUserEmailByUserID")
	defer span.End()

	row, err := p.query.GetPrimaryUserEmailByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.UserEmail{}, domain.ErrPrimaryEmailNotFound
		}
		return domain.UserEmail{}, err
	}
	return domain.UserEmail{
		ID:         row.ID,
		UserID:     row.UserID,
		Email:      row.Email,
		IsPrimary:  row.IsPrimary,
		CreatedAt:  row.CreatedAt.Time,
		VerifiedAt: fromPgTimestamptz(row.VerifiedAt),
		DeletedAt:  fromPgTimestamptz(row.DeletedAt),
	}, nil
}

func (p *Postgres) ListUserEmailsByUserID(ctx context.Context, userID int64, includeDeleted bool) ([]domain.UserEmail, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ListUserEmailsByUserID")
	defer span.End()

	var rows []sqlc.UserEmail
	var err error
	if includeDeleted {
		rows, err = p.query.ListUserEmailsByUserIDAll(ctx, userID)
	} else {
		rows, err = p.query.ListUserEmailsByUserID(ctx, userID)
	}
	if err != nil {
		return nil, err
	}
	out := make([]domain.UserEmail, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.UserEmail{
			ID:         r.ID,
			UserID:     r.UserID,
			Email:      r.Email,
			IsPrimary:  r.IsPrimary,
			CreatedAt:  r.CreatedAt.Time,
			VerifiedAt: fromPgTimestamptz(r.VerifiedAt),
			DeletedAt:  fromPgTimestamptz(r.DeletedAt),
		})
	}
	return out, nil
}

func (p *Postgres) UpdateUserEmail(ctx context.Context, email domain.UserEmail) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdateUserEmail")
	defer span.End()

	err := p.query.UpdateUserEmail(ctx, sqlc.UpdateUserEmailParams{
		ID:         email.ID,
		Email:      email.Email,
		IsPrimary:  email.IsPrimary,
		VerifiedAt: pgTimestamptzPtr(email.VerifiedAt),
		DeletedAt:  pgTimestamptzPtr(email.DeletedAt),
	})
	if err != nil {
		return err
	}
	return nil
}

func (p *Postgres) SoftDeleteUserEmail(ctx context.Context, emailID int64, now pgtype.Timestamptz) error {
	// not used directly, keep for compat
	return nil
}

func (p *Postgres) SetPrimaryEmailTx(ctx context.Context, userID, emailID int64) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "SetPrimaryEmailTx")
	defer span.End()

	tx, err := p.conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := p.query.WithTx(tx)

	// ensure email belongs to user and not deleted
	row, err := qtx.GetUserEmailByID(ctx, emailID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrEmailNotFound
		}
		return err
	}
	if row.UserID != userID || row.DeletedAt.Valid {
		return domain.ErrEmailNotFound
	}
	if err := qtx.ClearPrimaryEmails(ctx, userID); err != nil {
		return err
	}
	if err := qtx.SetPrimaryEmail(ctx, emailID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Postgres) CountUserEmails(ctx context.Context, userID int64) (int, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CountUserEmails")
	defer span.End()

	cnt, err := p.query.CountUserEmails(ctx, userID)
	if err != nil {
		return 0, err
	}
	return int(cnt), nil
}
