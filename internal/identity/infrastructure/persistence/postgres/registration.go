package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/qarven/oryon-go/internal/identity/application"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

// isUniqueViolation reports whether err is a Postgres unique-constraint violation (23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError

	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CreateRegistrationFlow persists a pre-registration auth flow with its OTP
// challenges. No user row is created, so the identifiers stay unclaimed until
// ownership is proven via VerifyEmail. Sibling pending challenges for the same
// identifier are consumed so only the latest code is valid.
func (p *Postgres) CreateRegistrationFlow(
	ctx context.Context,
	flow domain.AuthFlow,
	challenges []domain.VerificationChallenge,
) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateRegistrationFlow")
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

	for _, ch := range challenges {
		err := wtx.CreateVerificationChallenge(ctx, sqlc.CreateVerificationChallengeParams{
			ID:          ch.ID,
			UserID:      pgInt8(ch.UserID),
			FlowID:      pgInt8(ch.FlowID),
			Identifier:  ch.Identifier,
			Purpose:     int16(ch.Purpose),
			Code:        ch.CodeHash,
			Attempts:    ch.Attempts,
			MaxAttempts: ch.MaxAttempts,
			IpAddress:   pgText(ch.IPAddress),
			ExpiresAt:   pgTz(ch.ExpiresAt),
			ConsumedAt:  pgTzPtr(ch.ConsumedAt),
			CreatedAt:   pgTz(ch.CreatedAt),
		})
		if err != nil {
			return err
		}

		err = wtx.ConsumeSiblingChallenges(ctx, sqlc.ConsumeSiblingChallengesParams{
			ConsumedAt: pgTz(ch.CreatedAt),
			Identifier: ch.Identifier,
			Purpose:    int16(ch.Purpose),
			ExceptID:   ch.ID,
		})
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// CompleteRegistration atomically materializes a verified registration: user,
// contact rows, password credential, flow completion, and challenge consumption.
// A unique violation (lost race against a concurrent verify) is mapped to
// domain.ErrIdentifierConflict so callers can return 409.
func (p *Postgres) CompleteRegistration(ctx context.Context, data application.CompleteRegistrationData) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CompleteRegistration")
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

	if err := wtx.CreateUser(ctx, sqlc.CreateUserParams{
		ID:        data.User.ID,
		Status:    data.User.Status.Value(),
		Name:      data.User.Name,
		CreatedAt: pgTz(data.User.CreatedAt),
		UpdatedAt: pgTz(data.User.UpdatedAt),
	}); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("create user: %w", domain.ErrIdentifierConflict)
		}

		return err
	}

	if data.UserEmail != nil {
		err := wtx.CreateUserEmail(ctx, sqlc.CreateUserEmailParams{
			ID:         data.UserEmail.ID,
			UserID:     data.UserEmail.UserID,
			Email:      data.UserEmail.Email,
			IsPrimary:  data.UserEmail.IsPrimary,
			CreatedAt:  pgTz(data.UserEmail.CreatedAt),
			VerifiedAt: pgTzPtr(data.UserEmail.VerifiedAt),
		})
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("create user email: %w", domain.ErrIdentifierConflict)
			}

			return err
		}
	}

	if data.UserPhone != nil {
		err := wtx.CreateUserPhoneNumber(ctx, sqlc.CreateUserPhoneNumberParams{
			ID:         data.UserPhone.ID,
			UserID:     data.UserPhone.UserID,
			Phone:      data.UserPhone.Phone,
			CreatedAt:  pgTz(data.UserPhone.CreatedAt),
			VerifiedAt: pgTzPtr(data.UserPhone.VerifiedAt),
		})
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("create user phone: %w", domain.ErrIdentifierConflict)
			}

			return err
		}
	}

	if err := wtx.CreatePasswordCredential(ctx, sqlc.CreatePasswordCredentialParams{
		UserID:            data.PassCred.UserID,
		Password:          data.PassCred.Password,
		PasswordChangedAt: pgTz(data.PassCred.PasswordChangedAt),
		CreatedAt:         pgTz(data.PassCred.CreatedAt),
		UpdatedAt:         pgTz(data.PassCred.UpdatedAt),
	}); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("create password credential: %w", domain.ErrIdentifierConflict)
		}

		return err
	}

	if err := wtx.UpdateAuthFlow(ctx, sqlc.UpdateAuthFlowParams{
		ID:          data.Flow.ID,
		FlowState:   data.Flow.FlowState.Value(),
		CompletedAt: pgTzPtr(data.Flow.CompletedAt),
	}); err != nil {
		return err
	}

	if err := wtx.UpdateVerificationChallenge(ctx, sqlc.UpdateVerificationChallengeParams{
		ID:         data.Challenge.ID,
		Attempts:   data.Challenge.Attempts,
		ConsumedAt: pgTzPtr(data.Challenge.ConsumedAt),
	}); err != nil {
		return err
	}

	if err := wtx.ConsumeSiblingChallenges(ctx, sqlc.ConsumeSiblingChallengesParams{
		ConsumedAt: pgTzPtr(data.Challenge.ConsumedAt),
		Identifier: data.Challenge.Identifier,
		Purpose:    int16(data.Challenge.Purpose),
		ExceptID:   data.Challenge.ID,
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
