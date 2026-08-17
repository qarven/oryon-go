package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) GetIdentityCredentialByIdentityID(
	ctx context.Context,
	identityID int64,
	credType domain.IdentityCredentialType,
) (*domain.IdentityCredential, error) {
	ctx, span := p.ins.Tracer("identity.infrastructure.persistence").Start(ctx, "GetIdentityCredentialByIdentityID")
	defer span.End()

	row, err := p.query.GetIdentityCredentialByIdentityID(ctx, sqlc.GetIdentityCredentialByIdentityIDParams{
		IdentityID: identityID,
		Type:       credType.ToValue(),
	})

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrIdentityCredentialNotFound
	}

	if err != nil {
		return nil, err
	}

	return toIdentityCredential(row.ID, row.IdentityID, row.Type, row.PasswordHash), nil
}

func toIdentityCredential(
	id, identityID int64,
	credentialType int16,
	passwordHash pgtype.Text,
) *domain.IdentityCredential {
	out := &domain.IdentityCredential{
		ID:           id,
		IdentityID:   identityID,
		Type:         domain.IdentityCredentialType(credentialType),
		PasswordHash: nil,
	}

	if passwordHash.Valid {
		out.PasswordHash = &passwordHash.String
	}

	return out
}
