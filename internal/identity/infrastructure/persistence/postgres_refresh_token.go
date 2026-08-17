package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) CreateRefreshToken(ctx context.Context, rt domain.RefreshToken) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateRefreshToken")
	defer span.End()

	return p.query.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		ID:         rt.ID,
		SessionID:  rt.SessionID,
		Token:      rt.TokenHash,
		IssuedAt:   pgTimestamptz(rt.IssuedAt),
		ExpiresAt:  pgTimestamptz(rt.ExpiresAt),
		RevokedAt:  pgTimestamptzPtr(rt.RevokedAt),
		ReplacedBy: pgInt8(rt.ReplacedBy),
		CreatedIp:  inetPtr(rt.CreatedIP),
	})
}

func (p *Postgres) GetRefreshTokenByHash(ctx context.Context, hash []byte) (domain.RefreshToken, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetRefreshTokenByHash")
	defer span.End()

	row, err := p.query.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.RefreshToken{}, domain.ErrRefreshTokenNotFound
		}
		return domain.RefreshToken{}, err
	}
	return domain.RefreshToken{
		ID:         row.ID,
		SessionID:  row.SessionID,
		TokenHash:  row.Token,
		IssuedAt:   row.IssuedAt.Time,
		ExpiresAt:  row.ExpiresAt.Time,
		RevokedAt:  fromPgTimestamptz(row.RevokedAt),
		ReplacedBy: fromPgInt8(row.ReplacedBy),
		CreatedIP:  fromInetPtr(row.CreatedIp),
	}, nil
}

func (p *Postgres) GetRefreshTokenByID(ctx context.Context, id int64) (domain.RefreshToken, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetRefreshTokenByID")
	defer span.End()

	row, err := p.query.GetRefreshTokenByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.RefreshToken{}, domain.ErrRefreshTokenNotFound
		}
		return domain.RefreshToken{}, err
	}
	return domain.RefreshToken{
		ID:         row.ID,
		SessionID:  row.SessionID,
		TokenHash:  row.Token,
		IssuedAt:   row.IssuedAt.Time,
		ExpiresAt:  row.ExpiresAt.Time,
		RevokedAt:  fromPgTimestamptz(row.RevokedAt),
		ReplacedBy: fromPgInt8(row.ReplacedBy),
		CreatedIP:  fromInetPtr(row.CreatedIp),
	}, nil
}

func (p *Postgres) UpdateRefreshToken(ctx context.Context, rt domain.RefreshToken) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdateRefreshToken")
	defer span.End()

	return p.query.UpdateRefreshToken(ctx, sqlc.UpdateRefreshTokenParams{
		ID:         rt.ID,
		RevokedAt:  pgTimestamptzPtr(rt.RevokedAt),
		ReplacedBy: pgInt8(rt.ReplacedBy),
	})
}

func (p *Postgres) RevokeRefreshTokensBySessionID(ctx context.Context, sessionID int64, at pgtype.Timestamptz) (int64, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "RevokeRefreshTokensBySessionID")
	defer span.End()

	tag, err := p.conn.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $2 WHERE session_id = $1 AND revoked_at IS NULL`, sessionID, at)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
