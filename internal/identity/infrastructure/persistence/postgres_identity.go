package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) CreateIdentity(ctx context.Context, ident domain.Identity) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateIdentity")
	defer span.End()

	return p.query.CreateIdentity(ctx, sqlc.CreateIdentityParams{
		ID:              ident.ID,
		UserID:          ident.UserID,
		Provider:        int16(ident.Provider),
		ProviderSubject: ident.ProviderSubject,
		CreatedAt:       pgTimestamptz(ident.CreatedAt),
		LastUsedAt:      pgTimestamptzPtr(ident.LastUsedAt),
		RevokedAt:       pgTimestamptzPtr(ident.RevokedAt),
	})
}

func (p *Postgres) GetIdentityByProviderSubject(ctx context.Context, provider domain.IdentityProvider, subject string) (domain.Identity, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetIdentityByProviderSubject")
	defer span.End()

	row, err := p.query.GetIdentityByProviderSubject(ctx, sqlc.GetIdentityByProviderSubjectParams{
		Provider:        int16(provider),
		ProviderSubject: subject,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Identity{}, domain.ErrIdentityNotFound
		}
		return domain.Identity{}, err
	}
	return domain.Identity{
		ID:              row.ID,
		UserID:          row.UserID,
		Provider:        domain.IdentityProvider(row.Provider),
		ProviderSubject: row.ProviderSubject,
		CreatedAt:       row.CreatedAt.Time,
		LastUsedAt:      fromPgTimestamptz(row.LastUsedAt),
		RevokedAt:       fromPgTimestamptz(row.RevokedAt),
	}, nil
}

func (p *Postgres) ListIdentitiesByUserID(ctx context.Context, userID int64) ([]domain.Identity, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ListIdentitiesByUserID")
	defer span.End()

	rows, err := p.query.ListIdentitiesByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Identity, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.Identity{
			ID:              r.ID,
			UserID:          r.UserID,
			Provider:        domain.IdentityProvider(r.Provider),
			ProviderSubject: r.ProviderSubject,
			CreatedAt:       r.CreatedAt.Time,
			LastUsedAt:      fromPgTimestamptz(r.LastUsedAt),
			RevokedAt:       fromPgTimestamptz(r.RevokedAt),
		})
	}
	return out, nil
}

func (p *Postgres) RevokeIdentity(ctx context.Context, id int64, now pgtype.Timestamptz) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "RevokeIdentity")
	defer span.End()

	return p.query.RevokeIdentity(ctx, sqlc.RevokeIdentityParams{
		ID:        id,
		RevokedAt: now,
	})
}
