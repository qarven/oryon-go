package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) CreatePasswordCredential(ctx context.Context, cred domain.PasswordCredential) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreatePasswordCredential")
	defer span.End()

	return p.query.CreatePasswordCredential(ctx, sqlc.CreatePasswordCredentialParams{
		UserID:            cred.UserID,
		Password:          cred.Password,
		PasswordChangedAt: pgTimestamptz(cred.PasswordChangedAt),
		CreatedAt:         pgTimestamptz(cred.CreatedAt),
		UpdatedAt:         pgTimestamptz(cred.UpdatedAt),
	})
}

func (p *Postgres) GetPasswordCredentialByUserID(ctx context.Context, userID int64) (domain.PasswordCredential, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetPasswordCredentialByUserID")
	defer span.End()

	row, err := p.query.GetPasswordCredentialByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.PasswordCredential{}, domain.ErrPasswordCredentialNotFound
		}
		return domain.PasswordCredential{}, err
	}
	return domain.PasswordCredential{
		UserID:            row.UserID,
		Password:          row.Password,
		PasswordChangedAt: row.PasswordChangedAt.Time,
		CreatedAt:         row.CreatedAt.Time,
		UpdatedAt:         row.UpdatedAt.Time,
	}, nil
}

func (p *Postgres) UpdatePasswordCredential(ctx context.Context, cred domain.PasswordCredential) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdatePasswordCredential")
	defer span.End()

	return p.query.UpdatePasswordCredential(ctx, sqlc.UpdatePasswordCredentialParams{
		UserID:            cred.UserID,
		Password:          cred.Password,
		PasswordChangedAt: pgTimestamptz(cred.PasswordChangedAt),
		UpdatedAt:         pgTimestamptz(cred.UpdatedAt),
	})
}

func (p *Postgres) UpsertPasswordCredential(ctx context.Context, cred domain.PasswordCredential) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpsertPasswordCredential")
	defer span.End()

	return p.query.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{
		UserID:            cred.UserID,
		Password:          cred.Password,
		PasswordChangedAt: pgTimestamptz(cred.PasswordChangedAt),
		CreatedAt:         pgTimestamptz(cred.CreatedAt),
		UpdatedAt:         pgTimestamptz(cred.UpdatedAt),
	})
}
