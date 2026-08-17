package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) CreateTotpFactor(ctx context.Context, totp domain.TotpFactor) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateTotpFactor")
	defer span.End()

	return p.query.CreateTotpFactor(ctx, sqlc.CreateTotpFactorParams{
		FactorID:  totp.FactorID,
		Secret:    totp.Secret,
		Algorithm: int16(totp.Algorithm),
		Digits:    totp.Digits,
		Period:    totp.Period,
		CreatedAt: pgTimestamptz(totp.CreatedAt),
	})
}

func (p *Postgres) GetTotpFactorByFactorID(ctx context.Context, factorID int64) (domain.TotpFactor, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetTotpFactorByFactorID")
	defer span.End()

	row, err := p.query.GetTotpFactorByFactorID(ctx, factorID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.TotpFactor{}, domain.ErrTotpFactorNotFound
		}
		return domain.TotpFactor{}, err
	}
	return domain.TotpFactor{
		FactorID:  row.FactorID,
		Secret:    row.Secret,
		Algorithm: domain.TotpAlgorithm(row.Algorithm),
		Digits:    row.Digits,
		Period:    row.Period,
		CreatedAt: row.CreatedAt.Time,
	}, nil
}

func (p *Postgres) UpdateTotpSecret(ctx context.Context, factorID int64, secret []byte) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdateTotpSecret")
	defer span.End()

	return p.query.UpdateTotpSecret(ctx, sqlc.UpdateTotpSecretParams{
		FactorID: factorID,
		Secret:   secret,
	})
}

func (p *Postgres) DeleteTotpFactor(ctx context.Context, factorID int64) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "DeleteTotpFactor")
	defer span.End()

	return p.query.DeleteTotpFactor(ctx, factorID)
}
