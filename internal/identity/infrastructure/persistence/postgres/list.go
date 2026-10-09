package postgres

import (
	"context"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) ListBackupCodesByUserID(ctx context.Context, userID domain.ID) ([]domain.BackupCode, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ListBackupCodesByUserID")
	defer span.End()

	rows, err := p.query.ListBackupCodesByUserID(ctx, pgUUID(userID))
	if err != nil {
		return nil, err
	}

	out := make([]domain.BackupCode, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.BackupCode{
			ID:        fromPgUUID(row.ID),
			UserID:    fromPgUUID(row.UserID),
			CodeHash:  row.Code,
			UsedAt:    fromPgTz(row.UsedAt),
			CreatedAt: row.CreatedAt.Time,
		})
	}

	return out, nil
}

func (p *Postgres) ListMfaFactorsByUserID(
	ctx context.Context,
	userID domain.ID,
	includeRevoked bool,
) ([]domain.MfaFactor, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ListMfaFactorsByUserID")
	defer span.End()

	var (
		rows []sqlc.MfaFactor
		err  error
	)
	if includeRevoked {
		rows, err = p.query.ListMfaFactorsByUserID(ctx, pgUUID(userID))
	} else {
		rows, err = p.query.ListMfaFactorsByUserIDActive(ctx, pgUUID(userID))
	}

	if err != nil {
		return nil, err
	}

	out := make([]domain.MfaFactor, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.MfaFactor{
			ID:         fromPgUUID(row.ID),
			UserID:     fromPgUUID(row.UserID),
			Type:       domain.MfaFactorType(row.Type),
			Name:       row.Name,
			CreatedAt:  row.CreatedAt.Time,
			VerifiedAt: fromPgTz(row.VerifiedAt),
			LastUsedAt: fromPgTz(row.LastUsedAt),
			RevokedAt:  fromPgTz(row.RevokedAt),
		})
	}

	return out, nil
}

func (p *Postgres) ListPendingChallengesByIdentifier(
	ctx context.Context,
	identifier string,
	purpose domain.VerificationPurpose,
) ([]domain.VerificationChallenge, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ListPendingChallengesByIdentifier")
	defer span.End()

	rows, err := p.query.ListPendingVerificationChallengesByIdentifier(
		ctx,
		sqlc.ListPendingVerificationChallengesByIdentifierParams{
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
