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

// insertAuthFlow stores an auth flow inside an ongoing transaction.
func insertAuthFlow(ctx context.Context, wtx *sqlc.Queries, flow domain.AuthFlow) error {
	ctxJSON, err := json.Marshal(flow.Context)
	if err != nil {
		ctxJSON = []byte(`{}`)
	}

	err = wtx.CreateAuthFlow(ctx, sqlc.CreateAuthFlowParams{
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
	})
	if err != nil {
		return err
	}

	return nil
}

// createVerificationChallengeTx inserts a challenge and consumes older
// sibling challenges for the same identifier+purpose so only the latest code
// stays valid.
func createVerificationChallengeTx(
	ctx context.Context,
	wtx *sqlc.Queries,
	challenge domain.VerificationChallenge,
) error {
	err := wtx.CreateVerificationChallenge(ctx, sqlc.CreateVerificationChallengeParams{
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
	})
	if err != nil {
		return err
	}

	return wtx.ConsumeSiblingChallenges(ctx, sqlc.ConsumeSiblingChallengesParams{
		ConsumedAt: pgTz(challenge.CreatedAt),
		Identifier: challenge.Identifier,
		Purpose:    int16(challenge.Purpose),
		ExceptID:   challenge.ID,
	})
}

func (p *Postgres) RotateRefreshToken(ctx context.Context, data application.RotateRefreshTokenData) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "RotateRefreshToken")
	defer span.End()

	transaction, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		rErr := transaction.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rolback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(transaction)

	err = wtx.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		ID:        data.NewRefreshToken.ID,
		SessionID: data.NewRefreshToken.SessionID,
		Token:     data.NewRefreshToken.TokenHash,
		IssuedAt:  pgTz(data.NewRefreshToken.IssuedAt),
		ExpiresAt: pgTz(data.NewRefreshToken.ExpiresAt),
		CreatedIp: pgText(data.NewRefreshToken.CreatedIP),
	})
	if err != nil {
		return err
	}

	err = wtx.UpdateRefreshToken(ctx, sqlc.UpdateRefreshTokenParams{
		ID:         data.OldRefreshToken.ID,
		RevokedAt:  pgTzPtr(data.OldRefreshToken.RevokedAt),
		ReplacedBy: pgInt8(data.OldRefreshToken.ReplacedBy),
	})
	if err != nil {
		return err
	}

	err = wtx.UpdateSession(ctx, sqlc.UpdateSessionParams{
		ID:            data.Session.ID,
		LastSeenAt:    pgTzPtr(data.Session.LastSeenAt),
		MfaVerifiedAt: pgTzPtr(data.Session.MFAVerifiedAt),
		RevokedAt:     pgTzPtr(data.Session.RevokedAt),
		ExpiresAt:     pgTz(data.Session.ExpiresAt),
	})
	if err != nil {
		return err
	}

	return transaction.Commit(ctx)
}

func (p *Postgres) RevokeSession(ctx context.Context, data application.RevokeSessionData) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "RevokeSession")
	defer span.End()

	transaction, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		rErr := transaction.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rolback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(transaction)

	err = wtx.RevokeRefreshToken(ctx, sqlc.RevokeRefreshTokenParams{
		ID:        data.RefreshToken.ID,
		RevokedAt: pgTzPtr(data.RefreshToken.RevokedAt),
	})
	if err != nil {
		return err
	}

	err = wtx.RevokeSession(ctx, sqlc.RevokeSessionParams{
		ID:        data.Session.ID,
		RevokedAt: pgTzPtr(data.Session.RevokedAt),
	})
	if err != nil {
		return err
	}

	return transaction.Commit(ctx)
}

func (p *Postgres) CreateLoginSession(ctx context.Context, data application.CreateLoginSessionData) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateLoginSession")
	defer span.End()

	transaction, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		rErr := transaction.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rolback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(transaction)

	err = wtx.CreateSession(ctx, sqlc.CreateSessionParams{
		ID:            data.Session.ID,
		UserID:        data.Session.UserID,
		Token:         data.Session.TokenHash,
		CreatedAt:     pgTz(data.Session.CreatedAt),
		ExpiresAt:     pgTz(data.Session.ExpiresAt),
		IpAddress:     pgText(data.Session.IPAddress),
		UserAgent:     pgText(data.Session.UserAgent),
		LastSeenAt:    pgTzPtr(data.Session.LastSeenAt),
		MfaVerifiedAt: pgTzPtr(data.Session.MFAVerifiedAt),
	})
	if err != nil {
		return err
	}

	err = wtx.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		ID:        data.RefreshToken.ID,
		SessionID: data.RefreshToken.SessionID,
		Token:     data.RefreshToken.TokenHash,
		IssuedAt:  pgTz(data.RefreshToken.IssuedAt),
		ExpiresAt: pgTz(data.RefreshToken.ExpiresAt),
		CreatedIp: pgText(data.RefreshToken.CreatedIP),
	})
	if err != nil {
		return err
	}

	return transaction.Commit(ctx)
}

func (p *Postgres) CompleteMfaLogin(ctx context.Context, data application.CompleteMfaLoginData) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CompleteMfaLogin")
	defer span.End()

	transaction, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		rErr := transaction.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rolback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(transaction)

	err = touchMfaLoginFactor(ctx, wtx, data.Factor)
	if err != nil {
		return err
	}

	err = markMfaLoginBackupCodeUsed(ctx, wtx, data.BackupCode)
	if err != nil {
		return err
	}

	err = persistMfaLoginSession(ctx, wtx, data)
	if err != nil {
		return err
	}

	return transaction.Commit(ctx)
}

// touchMfaLoginFactor records the last-used timestamp of the MFA factor
// used for the login, if any.
func touchMfaLoginFactor(ctx context.Context, wtx *sqlc.Queries, factor *domain.MfaFactor) error {
	if factor == nil {
		return nil
	}

	err := wtx.UpdateMfaFactorLastUsedAt(ctx, sqlc.UpdateMfaFactorLastUsedAtParams{
		ID:         factor.ID,
		LastUsedAt: pgTzPtr(factor.LastUsedAt),
	})
	if err != nil {
		return err
	}

	return nil
}

// markMfaLoginBackupCodeUsed marks the backup code used for the login, if any.
func markMfaLoginBackupCodeUsed(
	ctx context.Context,
	wtx *sqlc.Queries,
	backupCode *domain.BackupCode,
) error {
	if backupCode == nil {
		return nil
	}

	err := wtx.MarkBackupCodeUsed(ctx, sqlc.MarkBackupCodeUsedParams{
		ID:     backupCode.ID,
		UsedAt: pgTzPtr(backupCode.UsedAt),
	})
	if err != nil {
		return err
	}

	return nil
}

// persistMfaLoginSession stores the completed flow, the login session, and
// its refresh token.
func persistMfaLoginSession(
	ctx context.Context,
	wtx *sqlc.Queries,
	data application.CompleteMfaLoginData,
) error {
	err := wtx.UpdateAuthFlow(ctx, sqlc.UpdateAuthFlowParams{
		ID:          data.Flow.ID,
		FlowState:   data.Flow.FlowState.Value(),
		CompletedAt: pgTzPtr(data.Flow.CompletedAt),
	})
	if err != nil {
		return err
	}

	err = wtx.CreateSession(ctx, sqlc.CreateSessionParams{
		ID:            data.Session.ID,
		UserID:        data.Session.UserID,
		Token:         data.Session.TokenHash,
		CreatedAt:     pgTz(data.Session.CreatedAt),
		ExpiresAt:     pgTz(data.Session.ExpiresAt),
		IpAddress:     pgText(data.Session.IPAddress),
		UserAgent:     pgText(data.Session.UserAgent),
		LastSeenAt:    pgTzPtr(data.Session.LastSeenAt),
		MfaVerifiedAt: pgTzPtr(data.Session.MFAVerifiedAt),
	})
	if err != nil {
		return err
	}

	err = wtx.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		ID:        data.RefreshToken.ID,
		SessionID: data.RefreshToken.SessionID,
		Token:     data.RefreshToken.TokenHash,
		IssuedAt:  pgTz(data.RefreshToken.IssuedAt),
		ExpiresAt: pgTz(data.RefreshToken.ExpiresAt),
		CreatedIp: pgText(data.RefreshToken.CreatedIP),
	})
	if err != nil {
		return err
	}

	return nil
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

	transaction, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}

	defer func() {
		rErr := transaction.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rollback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(transaction)

	err = insertAuthFlow(ctx, wtx, flow)
	if err != nil {
		return err
	}

	err = insertRegistrationChallenges(ctx, wtx, challenges)
	if err != nil {
		return err
	}

	return transaction.Commit(ctx)
}

// insertRegistrationChallenges stores OTP challenges, consuming older sibling
// challenges for the same identifier so only the latest code stays valid.
func insertRegistrationChallenges(
	ctx context.Context,
	wtx *sqlc.Queries,
	challenges []domain.VerificationChallenge,
) error {
	for _, challenge := range challenges {
		err := wtx.CreateVerificationChallenge(ctx, sqlc.CreateVerificationChallengeParams{
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
		})
		if err != nil {
			return err
		}

		err = wtx.ConsumeSiblingChallenges(ctx, sqlc.ConsumeSiblingChallengesParams{
			ConsumedAt: pgTz(challenge.CreatedAt),
			Identifier: challenge.Identifier,
			Purpose:    int16(challenge.Purpose),
			ExceptID:   challenge.ID,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// CompleteRegistration atomically materializes a verified registration: user,
// contact rows, password credential, flow completion, and challenge consumption.
// A unique violation (lost race against a concurrent verify) is mapped to
// domain.ErrIdentifierConflict so callers can return 409.
func (p *Postgres) CompleteRegistration(ctx context.Context, data application.CompleteRegistrationData) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CompleteRegistration")
	defer span.End()

	transaction, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}

	defer func() {
		rErr := transaction.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rollback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(transaction)

	err = createRegistrationUser(ctx, wtx, data.User)
	if err != nil {
		return err
	}

	err = createRegistrationContacts(ctx, wtx, data.UserEmail, data.UserPhone)
	if err != nil {
		return err
	}

	err = createRegistrationCredential(ctx, wtx, data.PassCred)
	if err != nil {
		return err
	}

	err = completeRegistrationFlowState(ctx, wtx, data.Flow, data.Challenge)
	if err != nil {
		return err
	}

	return transaction.Commit(ctx)
}

// createRegistrationUser inserts the user row, mapping a lost unique race
// to domain.ErrIdentifierConflict.
func createRegistrationUser(ctx context.Context, wtx *sqlc.Queries, user domain.User) error {
	err := wtx.CreateUser(ctx, sqlc.CreateUserParams{
		ID:        user.ID,
		Status:    user.Status.Value(),
		Name:      user.Name,
		CreatedAt: pgTz(user.CreatedAt),
		UpdatedAt: pgTz(user.UpdatedAt),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("create user: %w", domain.ErrIdentifierConflict)
		}

		return err
	}

	return nil
}

// createRegistrationContacts inserts the optional email/phone rows, mapping
// lost unique races to domain.ErrIdentifierConflict.
func createRegistrationContacts(
	ctx context.Context,
	wtx *sqlc.Queries,
	userEmail *domain.UserEmail,
	userPhone *domain.UserPhoneNumber,
) error {
	if userEmail != nil {
		err := wtx.CreateUserEmail(ctx, sqlc.CreateUserEmailParams{
			ID:         userEmail.ID,
			UserID:     userEmail.UserID,
			Email:      userEmail.Email,
			IsPrimary:  userEmail.IsPrimary,
			CreatedAt:  pgTz(userEmail.CreatedAt),
			VerifiedAt: pgTzPtr(userEmail.VerifiedAt),
		})
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("create user email: %w", domain.ErrIdentifierConflict)
			}

			return err
		}
	}

	if userPhone != nil {
		err := wtx.CreateUserPhoneNumber(ctx, sqlc.CreateUserPhoneNumberParams{
			ID:         userPhone.ID,
			UserID:     userPhone.UserID,
			Phone:      userPhone.Phone,
			CreatedAt:  pgTz(userPhone.CreatedAt),
			VerifiedAt: pgTzPtr(userPhone.VerifiedAt),
		})
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("create user phone: %w", domain.ErrIdentifierConflict)
			}

			return err
		}
	}

	return nil
}

// createRegistrationCredential inserts the password credential, mapping a
// lost unique race to domain.ErrIdentifierConflict.
func createRegistrationCredential(
	ctx context.Context,
	wtx *sqlc.Queries,
	passCred domain.PasswordCredential,
) error {
	err := wtx.CreatePasswordCredential(ctx, sqlc.CreatePasswordCredentialParams{
		UserID:            passCred.UserID,
		Password:          passCred.Password,
		PasswordChangedAt: pgTz(passCred.PasswordChangedAt),
		CreatedAt:         pgTz(passCred.CreatedAt),
		UpdatedAt:         pgTz(passCred.UpdatedAt),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("create password credential: %w", domain.ErrIdentifierConflict)
		}

		return err
	}

	return nil
}

// completeRegistrationFlowState marks the flow completed, consumes the
// primary challenge, and consumes older sibling challenges.
func completeRegistrationFlowState(
	ctx context.Context,
	wtx *sqlc.Queries,
	flow domain.AuthFlow,
	challenge domain.VerificationChallenge,
) error {
	err := wtx.UpdateAuthFlow(ctx, sqlc.UpdateAuthFlowParams{
		ID:          flow.ID,
		FlowState:   flow.FlowState.Value(),
		CompletedAt: pgTzPtr(flow.CompletedAt),
	})
	if err != nil {
		return err
	}

	err = wtx.UpdateVerificationChallenge(ctx, sqlc.UpdateVerificationChallengeParams{
		ID:         challenge.ID,
		Attempts:   challenge.Attempts,
		ConsumedAt: pgTzPtr(challenge.ConsumedAt),
	})
	if err != nil {
		return err
	}

	err = wtx.ConsumeSiblingChallenges(ctx, sqlc.ConsumeSiblingChallengesParams{
		ConsumedAt: pgTzPtr(challenge.ConsumedAt),
		Identifier: challenge.Identifier,
		Purpose:    int16(challenge.Purpose),
		ExceptID:   challenge.ID,
	})
	if err != nil {
		return err
	}

	return nil
}

// ResendRegistrationCode inserts fresh OTP challenges for an existing
// registration flow. Older sibling challenges for the same
// identifier+purpose are consumed so only the latest codes stay valid.
func (p *Postgres) ResendRegistrationCode(ctx context.Context, challenges []domain.VerificationChallenge) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ResendRegistrationCode")
	defer span.End()

	transaction, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}

	defer func() {
		rErr := transaction.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rollback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(transaction)

	for _, challenge := range challenges {
		err := createVerificationChallengeTx(ctx, wtx, challenge)
		if err != nil {
			return err
		}
	}

	return transaction.Commit(ctx)
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

	transaction, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}

	defer func() {
		rErr := transaction.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rollback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(transaction)

	err = insertAuthFlow(ctx, wtx, flow)
	if err != nil {
		return err
	}

	err = createVerificationChallengeTx(ctx, wtx, challenge)
	if err != nil {
		return err
	}

	return transaction.Commit(ctx)
}

// CreatePasswordResetChallenge inserts a password-reset OTP challenge,
// consuming older sibling challenges so only the latest code stays valid.
func (p *Postgres) CreatePasswordResetChallenge(
	ctx context.Context,
	challenge domain.VerificationChallenge,
) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreatePasswordResetChallenge")
	defer span.End()

	transaction, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}

	defer func() {
		rErr := transaction.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rollback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(transaction)

	err = createVerificationChallengeTx(ctx, wtx, challenge)
	if err != nil {
		return err
	}

	return transaction.Commit(ctx)
}

// CompletePasswordReset updates the password credential and consumes the
// verification challenge atomically.
func (p *Postgres) CompletePasswordReset(
	ctx context.Context,
	data application.CompletePasswordResetData,
) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CompletePasswordReset")
	defer span.End()

	transaction, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}

	defer func() {
		rErr := transaction.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rollback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(transaction)

	err = wtx.UpdatePasswordCredential(ctx, sqlc.UpdatePasswordCredentialParams{
		UserID:            data.UserID,
		Password:          data.Password,
		PasswordChangedAt: pgTz(data.ChangedAt),
		UpdatedAt:         pgTz(data.UpdatedAt),
	})
	if err != nil {
		return err
	}

	err = wtx.UpdateVerificationChallenge(ctx, sqlc.UpdateVerificationChallengeParams{
		ID:         data.Challenge.ID,
		Attempts:   data.Challenge.Attempts,
		ConsumedAt: pgTzPtr(data.Challenge.ConsumedAt),
	})
	if err != nil {
		return err
	}

	err = wtx.ConsumeSiblingChallenges(ctx, sqlc.ConsumeSiblingChallengesParams{
		ConsumedAt: pgTzPtr(data.Challenge.ConsumedAt),
		Identifier: data.Challenge.Identifier,
		Purpose:    int16(data.Challenge.Purpose),
		ExceptID:   data.Challenge.ID,
	})
	if err != nil {
		return err
	}

	return transaction.Commit(ctx)
}
