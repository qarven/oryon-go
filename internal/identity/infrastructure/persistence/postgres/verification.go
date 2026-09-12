package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/qarven/oryon-go/internal/identity/application"
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

// ResendVerificationChallenge persists a re-issued OTP challenge for a
// registration flow. Older sibling challenges for the same
// identifier+purpose are consumed so only the latest code is valid, and the
// flow expiry is extended per the InitiateVerification contract.
func (p *Postgres) ResendVerificationChallenge(
	ctx context.Context,
	data application.ResendVerificationChallengeData,
) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ResendVerificationChallenge")
	defer span.End()

	tx, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}

	defer func() {
		rErr := tx.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rollback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(tx)

	if err := createVerificationChallengeTx(ctx, wtx, data.Challenge); err != nil {
		return err
	}

	if err := wtx.ExtendAuthFlowExpiry(ctx, sqlc.ExtendAuthFlowExpiryParams{
		ExpiresAt: pgTz(data.Flow.ExpiresAt),
		ID:        data.Flow.ID,
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// CreateFlowWithChallenge persists a new auth flow together with its first
// OTP challenge. Older sibling challenges for the same identifier+purpose
// are consumed so only the latest code is valid.
func (p *Postgres) CreateFlowWithChallenge(
	ctx context.Context,
	flow domain.AuthFlow,
	challenge domain.VerificationChallenge,
) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateFlowWithChallenge")
	defer span.End()

	tx, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}

	defer func() {
		rErr := tx.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rollback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(tx)

	ctxJSON, err := json.Marshal(flow.Context)
	if err != nil {
		ctxJSON = []byte(`{}`)
	}

	if err := wtx.CreateAuthFlow(ctx, sqlc.CreateAuthFlowParams{
		ID:          flow.ID,
		UserID:      pgInt8(flow.UserID),
		FlowType:    flow.FlowType.Value(),
		FlowState:   flow.FlowState.Value(),
		IpAddress:   pgText(flow.IPAddress),
		UserAgent:   pgText(flow.UserAgent),
		Context:     ctxJSON,
		CreatedAt:   pgTz(flow.CreatedAt),
		ExpiresAt:   pgTz(flow.ExpiresAt),
		CompletedAt: pgTzPtr(flow.CompletedAt),
	}); err != nil {
		return err
	}

	if err := createVerificationChallengeTx(ctx, wtx, challenge); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// createVerificationChallengeTx inserts a challenge and consumes older
// sibling challenges for the same identifier+purpose so only the latest code
// stays valid.
func createVerificationChallengeTx(
	ctx context.Context,
	wtx *sqlc.Queries,
	challenge domain.VerificationChallenge,
) error {
	if err := wtx.CreateVerificationChallenge(ctx, sqlc.CreateVerificationChallengeParams{
		ID:          challenge.ID,
		UserID:      pgInt8(challenge.UserID),
		FlowID:      pgInt8(challenge.FlowID),
		Identifier:  challenge.Identifier,
		Purpose:     int16(challenge.Purpose),
		Code:        challenge.CodeHash,
		Attempts:    challenge.Attempts,
		MaxAttempts: challenge.MaxAttempts,
		IpAddress:   pgText(challenge.IPAddress),
		ExpiresAt:   pgTz(challenge.ExpiresAt),
		ConsumedAt:  pgTzPtr(challenge.ConsumedAt),
		CreatedAt:   pgTz(challenge.CreatedAt),
	}); err != nil {
		return err
	}

	return wtx.ConsumeSiblingChallenges(ctx, sqlc.ConsumeSiblingChallengesParams{
		ConsumedAt: pgTz(challenge.CreatedAt),
		Identifier: challenge.Identifier,
		Purpose:    int16(challenge.Purpose),
		ExceptID:   challenge.ID,
	})
}
