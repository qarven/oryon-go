package postgres

// import (
// 	"context"
// 	"errors"

// 	"github.com/jackc/pgx/v5"
// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/sqlc"
// )

// func (p *Postgres) CreatePasswordCredential(ctx context.Context, cred domain.PasswordCredential) error {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreatePasswordCredential")
// 	defer span.End()

// 	return p.query.CreatePasswordCredential(ctx, sqlc.CreatePasswordCredentialParams{
// 		UserID:            cred.UserID,
// 		Password:          cred.Password,
// 		PasswordChangedAt: pgTz(cred.PasswordChangedAt),
// 		CreatedAt:         pgTz(cred.CreatedAt),
// 		UpdatedAt:         pgTz(cred.UpdatedAt),
// 	})
// }

// func (p *Postgres) UpdatePasswordCredential(ctx context.Context, cred domain.PasswordCredential) error {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdatePasswordCredential")
// 	defer span.End()

// 	return p.query.UpdatePasswordCredential(ctx, sqlc.UpdatePasswordCredentialParams{
// 		UserID:            cred.UserID,
// 		Password:          cred.Password,
// 		PasswordChangedAt: pgTz(cred.PasswordChangedAt),
// 		UpdatedAt:         pgTz(cred.UpdatedAt),
// 	})
// }

// func (p *Postgres) UpsertPasswordCredential(ctx context.Context, cred domain.PasswordCredential) error {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpsertPasswordCredential")
// 	defer span.End()

// 	return p.query.UpsertPasswordCredential(ctx, sqlc.UpsertPasswordCredentialParams{
// 		UserID:            cred.UserID,
// 		Password:          cred.Password,
// 		PasswordChangedAt: pgTz(cred.PasswordChangedAt),
// 		CreatedAt:         pgTz(cred.CreatedAt),
// 		UpdatedAt:         pgTz(cred.UpdatedAt),
// 	})
// }
