package postgres

// import (
// 	"context"
// 	"errors"

// 	"github.com/jackc/pgx/v5"
// 	"github.com/jackc/pgx/v5/pgtype"
// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/sqlc"
// )

// func (p *Postgres) GetRefreshTokenByID(ctx context.Context, id int64) (domain.RefreshToken, error) {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetRefreshTokenByID")
// 	defer span.End()

// 	row, err := p.query.GetRefreshTokenByID(ctx, id)
// 	if err != nil {
// 		if errors.Is(err, pgx.ErrNoRows) {
// 			return domain.RefreshToken{}, domain.ErrRefreshTokenNotFound
// 		}
// 		return domain.RefreshToken{}, err
// 	}
// 	return domain.RefreshToken{
// 		ID:         row.ID,
// 		SessionID:  row.SessionID,
// 		TokenHash:  row.Token,
// 		IssuedAt:   row.IssuedAt.Time,
// 		ExpiresAt:  row.ExpiresAt.Time,
// 		RevokedAt:  fromPgTz(row.RevokedAt),
// 		ReplacedBy: fromPgInt8(row.ReplacedBy),
// 		CreatedIP:  fromPgText(row.CreatedIp),
// 	}, nil
// }

// func (p *Postgres) RevokeRefreshTokensBySessionID(ctx context.Context, sessionID int64, at pgtype.Timestamptz) (int64, error) {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "RevokeRefreshTokensBySessionID")
// 	defer span.End()

// 	tag, err := p.conn.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $2 WHERE session_id = $1 AND revoked_at IS NULL`, sessionID, at)
// 	if err != nil {
// 		return 0, err
// 	}
// 	return tag.RowsAffected(), nil
// }
