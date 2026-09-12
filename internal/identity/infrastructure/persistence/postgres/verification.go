package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) CreateVerificationChallenge(ctx context.Context, vc domain.VerificationChallenge) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateVerificationChallenge")
	defer span.End()

	return p.query.CreateVerificationChallenge(ctx, sqlc.CreateVerificationChallengeParams{
		ID:          vc.ID,
		UserID:      pgInt8(vc.UserID),
		FlowID:      pgInt8(vc.FlowID),
		Identifier:  vc.Identifier,
		Purpose:     int16(vc.Purpose),
		Code:        vc.CodeHash,
		Attempts:    vc.Attempts,
		MaxAttempts: vc.MaxAttempts,
		IpAddress:   pgText(vc.IPAddress),
		ExpiresAt:   pgTz(vc.ExpiresAt),
		ConsumedAt:  pgTzPtr(vc.ConsumedAt),
		CreatedAt:   pgTz(vc.CreatedAt),
	})
}

func toVerificationChallenge(row sqlc.VerificationChallenge) domain.VerificationChallenge {
	return domain.VerificationChallenge{
		ID:          row.ID,
		UserID:      fromPgInt8(row.UserID),
		FlowID:      fromPgInt8(row.FlowID),
		Identifier:  row.Identifier,
		Purpose:     domain.VerificationPurpose(row.Purpose),
		CodeHash:    row.Code,
		Attempts:    row.Attempts,
		MaxAttempts: row.MaxAttempts,
		IPAddress:   fromPgText(row.IpAddress),
		ExpiresAt:   row.ExpiresAt.Time,
		ConsumedAt:  fromPgTz(row.ConsumedAt),
		CreatedAt:   row.CreatedAt.Time,
	}
}

func (p *Postgres) GetVerificationChallengeByID(
	ctx context.Context,
	id int64,
) (*domain.VerificationChallenge, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetVerificationChallengeByID")
	defer span.End()

	row, err := p.query.GetVerificationChallengeByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrVerificationNotFound
	}

	if err != nil {
		return nil, err
	}

	vc := toVerificationChallenge(row)

	return &vc, nil
}

func (p *Postgres) ListPendingChallengesByIdentifier(
	ctx context.Context,
	identifier string,
	purpose domain.VerificationPurpose,
) ([]domain.VerificationChallenge, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ListPendingChallengesByIdentifier")
	defer span.End()

	rows, err := p.query.ListPendingVerificationChallengesByIdentifier(ctx, sqlc.ListPendingVerificationChallengesByIdentifierParams{
		Identifier: identifier,
		Purpose:    int16(purpose),
	})
	if err != nil {
		return nil, err
	}

	out := make([]domain.VerificationChallenge, 0, len(rows))
	for _, r := range rows {
		out = append(out, toVerificationChallenge(r))
	}

	return out, nil
}

func (p *Postgres) UpdateVerificationChallenge(ctx context.Context, vc domain.VerificationChallenge) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdateVerificationChallenge")
	defer span.End()

	return p.query.UpdateVerificationChallenge(ctx, sqlc.UpdateVerificationChallengeParams{
		ID:         vc.ID,
		Attempts:   vc.Attempts,
		ConsumedAt: pgTzPtr(vc.ConsumedAt),
	})
}
