package postgres

// import (
// 	"context"
// 	"errors"
// 	"time"

// 	"github.com/jackc/pgx/v5"
// 	"github.com/jackc/pgx/v5/pgtype"
// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/sqlc"
// )

// func (p *Postgres) CreateSession(ctx context.Context, sess domain.Session) error {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateSession")
// 	defer span.End()

// 	return p.query.CreateSession(ctx, sqlc.CreateSessionParams{
// 		ID:            sess.ID,
// 		UserID:        sess.UserID,
// 		Token:         sess.TokenHash,
// 		CreatedAt:     pgTz(sess.CreatedAt),
// 		ExpiresAt:     pgTz(sess.ExpiresAt),
// 		LastSeenAt:    pgTzPtr(sess.LastSeenAt),
// 		RevokedAt:     pgTzPtr(sess.RevokedAt),
// 		IpAddress:     pgText(sess.IPAddress),
// 		UserAgent:     pgText(sess.UserAgent),
// 		MfaVerifiedAt: pgTzPtr(sess.MFAVerifiedAt),
// 	})
// }

// func (p *Postgres) GetSessionByTokenHash(ctx context.Context, hash []byte) (domain.Session, error) {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetSessionByTokenHash")
// 	defer span.End()

// 	row, err := p.query.GetSessionByTokenHash(ctx, hash)
// 	if err != nil {
// 		if errors.Is(err, pgx.ErrNoRows) {
// 			return domain.Session{}, domain.ErrSessionNotFound
// 		}
// 		return domain.Session{}, err
// 	}
// 	return domain.Session{
// 		ID:            row.ID,
// 		UserID:        row.UserID,
// 		TokenHash:     row.Token,
// 		CreatedAt:     row.CreatedAt.Time,
// 		ExpiresAt:     row.ExpiresAt.Time,
// 		LastSeenAt:    fromPgTz(row.LastSeenAt),
// 		RevokedAt:     fromPgTz(row.RevokedAt),
// 		IPAddress:     fromPgText(row.IpAddress),
// 		UserAgent:     fromPgText(row.UserAgent),
// 		MFAVerifiedAt: fromPgTz(row.MfaVerifiedAt),
// 	}, nil
// }

// func (p *Postgres) ListSessionsByUserID(ctx context.Context, userID int64, includeRevoked, includeExpired bool) ([]domain.Session, error) {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ListSessionsByUserID")
// 	defer span.End()

// 	rows, err := p.query.ListSessionsByUserIDAll(ctx, userID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	now := time.Now()
// 	out := make([]domain.Session, 0, len(rows))
// 	for _, r := range rows {
// 		sess := domain.Session{
// 			ID:            r.ID,
// 			UserID:        r.UserID,
// 			TokenHash:     r.Token,
// 			CreatedAt:     r.CreatedAt.Time,
// 			ExpiresAt:     r.ExpiresAt.Time,
// 			LastSeenAt:    fromPgTz(r.LastSeenAt),
// 			RevokedAt:     fromPgTz(r.RevokedAt),
// 			IPAddress:     fromPgText(r.IpAddress),
// 			UserAgent:     fromPgText(r.UserAgent),
// 			MFAVerifiedAt: fromPgTz(r.MfaVerifiedAt),
// 		}
// 		if !includeRevoked && sess.IsRevoked() {
// 			continue
// 		}
// 		if !includeExpired && sess.IsExpired(now) {
// 			continue
// 		}
// 		out = append(out, sess)
// 	}
// 	return out, nil
// }

// func (p *Postgres) RevokeSession(ctx context.Context, id int64, at pgtype.Timestamptz) error {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "RevokeSession")
// 	defer span.End()

// 	return p.query.RevokeSession(ctx, sqlc.RevokeSessionParams{
// 		ID:        id,
// 		RevokedAt: at,
// 	})
// }

// func (p *Postgres) RevokeAllOtherSessions(ctx context.Context, userID, currentSessionID int64, at pgtype.Timestamptz) (int64, error) {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "RevokeAllOtherSessions")
// 	defer span.End()

// 	tag, err := p.conn.Exec(ctx, `UPDATE sessions SET revoked_at = $3 WHERE user_id = $1 AND id != $2 AND revoked_at IS NULL`, userID, currentSessionID, at)
// 	if err != nil {
// 		return 0, err
// 	}
// 	return tag.RowsAffected(), nil
// }

// func (p *Postgres) TouchSession(ctx context.Context, id int64, at pgtype.Timestamptz) error {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "TouchSession")
// 	defer span.End()

// 	return p.query.TouchSession(ctx, sqlc.TouchSessionParams{
// 		ID:         id,
// 		LastSeenAt: at,
// 	})
// }
