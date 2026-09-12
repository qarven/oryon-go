package postgres

// import (
// 	"context"
// 	"errors"

// 	"github.com/jackc/pgx/v5"
// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/sqlc"
// )

// func (p *Postgres) CreateMfaFactor(ctx context.Context, factor domain.MfaFactor) error {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateMfaFactor")
// 	defer span.End()

// 	return p.query.CreateMfaFactor(ctx, sqlc.CreateMfaFactorParams{
// 		ID:         factor.ID,
// 		UserID:     factor.UserID,
// 		Type:       int16(factor.Type),
// 		Name:       factor.Name,
// 		CreatedAt:  pgTz(factor.CreatedAt),
// 		VerifiedAt: pgTzPtr(factor.VerifiedAt),
// 		LastUsedAt: pgTzPtr(factor.LastUsedAt),
// 		RevokedAt:  pgTzPtr(factor.RevokedAt),
// 	})
// }

// func (p *Postgres) GetMfaFactorByID(ctx context.Context, id int64) (domain.MfaFactor, error) {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetMfaFactorByID")
// 	defer span.End()

// 	row, err := p.query.GetMfaFactorByID(ctx, id)
// 	if err != nil {
// 		if errors.Is(err, pgx.ErrNoRows) {
// 			return domain.MfaFactor{}, domain.ErrMfaFactorNotFound
// 		}
// 		return domain.MfaFactor{}, err
// 	}
// 	return domain.MfaFactor{
// 		ID:         row.ID,
// 		UserID:     row.UserID,
// 		Type:       domain.MfaFactorType(row.Type),
// 		Name:       row.Name,
// 		CreatedAt:  row.CreatedAt.Time,
// 		VerifiedAt: fromPgTz(row.VerifiedAt),
// 		LastUsedAt: fromPgTz(row.LastUsedAt),
// 		RevokedAt:  fromPgTz(row.RevokedAt),
// 	}, nil
// }

// func (p *Postgres) UpdateMfaFactor(ctx context.Context, factor domain.MfaFactor) error {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdateMfaFactor")
// 	defer span.End()

// 	return p.query.UpdateMfaFactor(ctx, sqlc.UpdateMfaFactorParams{
// 		ID:         factor.ID,
// 		Name:       factor.Name,
// 		VerifiedAt: pgTzPtr(factor.VerifiedAt),
// 		LastUsedAt: pgTzPtr(factor.LastUsedAt),
// 		RevokedAt:  pgTzPtr(factor.RevokedAt),
// 	})
// }

// func (p *Postgres) DeleteMfaFactor(ctx context.Context, id int64) error {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "DeleteMfaFactor")
// 	defer span.End()

// 	tag, err := p.conn.Exec(ctx, `DELETE FROM mfa_factors WHERE id = $1`, id)
// 	if err != nil {
// 		return err
// 	}
// 	if tag.RowsAffected() == 0 {
// 		return domain.ErrMfaFactorNotFound
// 	}
// 	return nil
// }
