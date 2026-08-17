package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) CreateMfaFactor(ctx context.Context, factor domain.MfaFactor) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateMfaFactor")
	defer span.End()

	return p.query.CreateMfaFactor(ctx, sqlc.CreateMfaFactorParams{
		ID:         factor.ID,
		UserID:     factor.UserID,
		Type:       int16(factor.Type),
		Name:       factor.Name,
		CreatedAt:  pgTimestamptz(factor.CreatedAt),
		VerifiedAt: pgTimestamptzPtr(factor.VerifiedAt),
		LastUsedAt: pgTimestamptzPtr(factor.LastUsedAt),
		RevokedAt:  pgTimestamptzPtr(factor.RevokedAt),
	})
}

func (p *Postgres) GetMfaFactorByID(ctx context.Context, id int64) (domain.MfaFactor, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetMfaFactorByID")
	defer span.End()

	row, err := p.query.GetMfaFactorByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.MfaFactor{}, domain.ErrMfaFactorNotFound
		}
		return domain.MfaFactor{}, err
	}
	return domain.MfaFactor{
		ID:         row.ID,
		UserID:     row.UserID,
		Type:       domain.MfaFactorType(row.Type),
		Name:       row.Name,
		CreatedAt:  row.CreatedAt.Time,
		VerifiedAt: fromPgTimestamptz(row.VerifiedAt),
		LastUsedAt: fromPgTimestamptz(row.LastUsedAt),
		RevokedAt:  fromPgTimestamptz(row.RevokedAt),
	}, nil
}

func (p *Postgres) ListMfaFactorsByUserID(ctx context.Context, userID int64, includeRevoked bool) ([]domain.MfaFactor, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ListMfaFactorsByUserID")
	defer span.End()

	var rows []sqlc.MfaFactor
	var err error
	if includeRevoked {
		rows, err = p.query.ListMfaFactorsByUserID(ctx, userID)
	} else {
		rows, err = p.query.ListMfaFactorsByUserIDActive(ctx, userID)
	}
	if err != nil {
		return nil, err
	}
	out := make([]domain.MfaFactor, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.MfaFactor{
			ID:         r.ID,
			UserID:     r.UserID,
			Type:       domain.MfaFactorType(r.Type),
			Name:       r.Name,
			CreatedAt:  r.CreatedAt.Time,
			VerifiedAt: fromPgTimestamptz(r.VerifiedAt),
			LastUsedAt: fromPgTimestamptz(r.LastUsedAt),
			RevokedAt:  fromPgTimestamptz(r.RevokedAt),
		})
	}
	return out, nil
}

func (p *Postgres) UpdateMfaFactor(ctx context.Context, factor domain.MfaFactor) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdateMfaFactor")
	defer span.End()

	return p.query.UpdateMfaFactor(ctx, sqlc.UpdateMfaFactorParams{
		ID:         factor.ID,
		Name:       factor.Name,
		VerifiedAt: pgTimestamptzPtr(factor.VerifiedAt),
		LastUsedAt: pgTimestamptzPtr(factor.LastUsedAt),
		RevokedAt:  pgTimestamptzPtr(factor.RevokedAt),
	})
}

func (p *Postgres) DeleteMfaFactor(ctx context.Context, id int64) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "DeleteMfaFactor")
	defer span.End()

	tag, err := p.conn.Exec(ctx, `DELETE FROM mfa_factors WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrMfaFactorNotFound
	}
	return nil
}
