package persistence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) CreateBackupCodes(ctx context.Context, codes []domain.BackupCode) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateBackupCodes")
	defer span.End()

	if len(codes) == 0 {
		return nil
	}
	tx, err := p.conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := p.query.WithTx(tx)
	for _, c := range codes {
		if err := qtx.CreateBackupCode(ctx, sqlc.CreateBackupCodeParams{
			ID:        c.ID,
			UserID:    c.UserID,
			Code:      c.CodeHash,
			UsedAt:    pgTimestamptzPtr(c.UsedAt),
			CreatedAt: pgTimestamptz(c.CreatedAt),
		}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (p *Postgres) ListBackupCodesByUserID(ctx context.Context, userID int64) ([]domain.BackupCode, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ListBackupCodesByUserID")
	defer span.End()

	rows, err := p.query.ListBackupCodesByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.BackupCode, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.BackupCode{
			ID:        r.ID,
			UserID:    r.UserID,
			CodeHash:  r.Code,
			UsedAt:    fromPgTimestamptz(r.UsedAt),
			CreatedAt: r.CreatedAt.Time,
		})
	}
	return out, nil
}

func (p *Postgres) CountUnusedBackupCodes(ctx context.Context, userID int64) (int32, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CountUnusedBackupCodes")
	defer span.End()

	cnt, err := p.query.CountUnusedBackupCodes(ctx, userID)
	if err != nil {
		return 0, err
	}
	return int32(cnt), nil
}

func (p *Postgres) DeleteBackupCodesByUserID(ctx context.Context, userID int64) (int64, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "DeleteBackupCodesByUserID")
	defer span.End()

	tag, err := p.conn.Exec(ctx, `DELETE FROM backup_codes WHERE user_id = $1`, userID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (p *Postgres) FindUnusedBackupCodeByHash(ctx context.Context, userID int64, hash []byte) (domain.BackupCode, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "FindUnusedBackupCodeByHash")
	defer span.End()

	row, err := p.query.FindUnusedBackupCodeByHash(ctx, sqlc.FindUnusedBackupCodeByHashParams{
		UserID: userID,
		Code:   hash,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.BackupCode{}, domain.ErrBackupCodeNotFound
		}
		return domain.BackupCode{}, err
	}
	return domain.BackupCode{
		ID:        row.ID,
		UserID:    row.UserID,
		CodeHash:  row.Code,
		UsedAt:    fromPgTimestamptz(row.UsedAt),
		CreatedAt: row.CreatedAt.Time,
	}, nil
}

func (p *Postgres) MarkBackupCodeUsed(ctx context.Context, id int64, at pgtype.Timestamptz) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "MarkBackupCodeUsed")
	defer span.End()

	return p.query.MarkBackupCodeUsed(ctx, sqlc.MarkBackupCodeUsedParams{
		ID:     id,
		UsedAt: at,
	})
}

func (p *Postgres) GetBackupCodesForVerification(ctx context.Context, userID int64) ([]domain.BackupCode, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetBackupCodesForVerification")
	defer span.End()

	rows, err := p.query.GetBackupCodesForVerification(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.BackupCode, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.BackupCode{
			ID:        r.ID,
			UserID:    r.UserID,
			CodeHash:  r.Code,
			UsedAt:    fromPgTimestamptz(r.UsedAt),
			CreatedAt: r.CreatedAt.Time,
		})
	}
	return out, nil
}
