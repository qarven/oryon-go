package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
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
		IpAddress:   inetPtr(vc.IPAddress),
		ExpiresAt:   pgTimestamptz(vc.ExpiresAt),
		ConsumedAt:  pgTimestamptzPtr(vc.ConsumedAt),
		CreatedAt:   pgTimestamptz(vc.CreatedAt),
	})
}

func (p *Postgres) GetVerificationChallengeByID(ctx context.Context, id int64) (domain.VerificationChallenge, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetVerificationChallengeByID")
	defer span.End()

	row, err := p.query.GetVerificationChallengeByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.VerificationChallenge{}, domain.ErrVerificationNotFound
		}
		return domain.VerificationChallenge{}, err
	}
	return domain.VerificationChallenge{
		ID:          row.ID,
		UserID:      fromPgInt8(row.UserID),
		FlowID:      fromPgInt8(row.FlowID),
		Identifier:  row.Identifier,
		Purpose:     domain.VerificationPurpose(row.Purpose),
		CodeHash:    row.Code,
		Attempts:    row.Attempts,
		MaxAttempts: row.MaxAttempts,
		IPAddress:   fromInetPtr(row.IpAddress),
		ExpiresAt:   row.ExpiresAt.Time,
		ConsumedAt:  fromPgTimestamptz(row.ConsumedAt),
		CreatedAt:   row.CreatedAt.Time,
	}, nil
}

func (p *Postgres) GetVerificationByIdentifierPurpose(ctx context.Context, identifier string, purpose domain.VerificationPurpose) ([]domain.VerificationChallenge, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetVerificationByIdentifierPurpose")
	defer span.End()

	rows, err := p.query.GetVerificationByIdentifierPurpose(ctx, sqlc.GetVerificationByIdentifierPurposeParams{
		Identifier: identifier,
		Purpose:    int16(purpose),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.VerificationChallenge, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.VerificationChallenge{
			ID:          r.ID,
			UserID:      fromPgInt8(r.UserID),
			FlowID:      fromPgInt8(r.FlowID),
			Identifier:  r.Identifier,
			Purpose:     domain.VerificationPurpose(r.Purpose),
			CodeHash:    r.Code,
			Attempts:    r.Attempts,
			MaxAttempts: r.MaxAttempts,
			IPAddress:   fromInetPtr(r.IpAddress),
			ExpiresAt:   r.ExpiresAt.Time,
			ConsumedAt:  fromPgTimestamptz(r.ConsumedAt),
			CreatedAt:   r.CreatedAt.Time,
		})
	}
	return out, nil
}

func (p *Postgres) GetVerificationChallengeByHash(ctx context.Context, hash []byte, purpose domain.VerificationPurpose) (domain.VerificationChallenge, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetVerificationChallengeByHash")
	defer span.End()

	row, err := p.query.GetVerificationChallengeByHash(ctx, sqlc.GetVerificationChallengeByHashParams{
		Code:    hash,
		Purpose: int16(purpose),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.VerificationChallenge{}, domain.ErrVerificationNotFound
		}
		return domain.VerificationChallenge{}, err
	}
	return domain.VerificationChallenge{
		ID:          row.ID,
		UserID:      fromPgInt8(row.UserID),
		FlowID:      fromPgInt8(row.FlowID),
		Identifier:  row.Identifier,
		Purpose:     domain.VerificationPurpose(row.Purpose),
		CodeHash:    row.Code,
		Attempts:    row.Attempts,
		MaxAttempts: row.MaxAttempts,
		IPAddress:   fromInetPtr(row.IpAddress),
		ExpiresAt:   row.ExpiresAt.Time,
		ConsumedAt:  fromPgTimestamptz(row.ConsumedAt),
		CreatedAt:   row.CreatedAt.Time,
	}, nil
}

func (p *Postgres) UpdateVerificationChallenge(ctx context.Context, vc domain.VerificationChallenge) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdateVerificationChallenge")
	defer span.End()

	return p.query.UpdateVerificationChallenge(ctx, sqlc.UpdateVerificationChallengeParams{
		ID:         vc.ID,
		Attempts:   vc.Attempts,
		ConsumedAt: pgTimestamptzPtr(vc.ConsumedAt),
	})
}

func (p *Postgres) IncrementVerificationAttempts(ctx context.Context, id int64) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "IncrementVerificationAttempts")
	defer span.End()

	return p.query.IncrementVerificationAttempts(ctx, id)
}

func (p *Postgres) ConsumeVerificationChallenge(ctx context.Context, id int64, at pgtype.Timestamptz) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ConsumeVerificationChallenge")
	defer span.End()

	return p.query.ConsumeVerificationChallenge(ctx, sqlc.ConsumeVerificationChallengeParams{
		ID:         id,
		ConsumedAt: at,
	})
}
