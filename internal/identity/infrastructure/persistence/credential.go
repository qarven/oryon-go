package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) GetCredentialByUserID(ctx context.Context, uID int64, credType domain.CredentialType) (
	*domain.Credential, error) {
	ctx, span := p.ins.Tracer("identity.infrastructure.persistence").Start(ctx, "GetCredentialByUserID")
	defer span.End()

	row, err := p.query.GetCredentialByUserID(ctx, sqlc.GetCredentialByUserIDParams{
		UserID: uID,
		Type:   credType.ToValue(),
	})

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrCredentialNotFound
	}

	if err != nil {
		return nil, err
	}

	return toCredential(row.ID, row.UserID, row.Type, row.PasswordHash), nil
}

func toCredential(id, userID int64, credentialType int16, passwordHash pgtype.Text) *domain.Credential {
	out := &domain.Credential{
		ID:           id,
		UserID:       userID,
		Type:         domain.CredentialType(credentialType),
		PasswordHash: nil,
	}

	if passwordHash.Valid {
		out.PasswordHash = &passwordHash.String
	}

	return out
}
