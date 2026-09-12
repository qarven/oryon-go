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

func (p *Postgres) RotateRefreshToken(ctx context.Context, data application.RotateRefreshTokenData) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "RotateRefreshToken")
	defer span.End()

	tx, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		rErr := tx.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rolback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(tx)

	if err := wtx.UpdateRefreshToken(ctx, sqlc.UpdateRefreshTokenParams{
		ID:         data.OldRefreshToken.ID,
		RevokedAt:  pgTzPtr(data.OldRefreshToken.RevokedAt),
		ReplacedBy: pgInt8(data.OldRefreshToken.ReplacedBy),
	}); err != nil {
		return err
	}

	if err := wtx.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		ID:        data.NewRefreshToken.ID,
		SessionID: data.NewRefreshToken.SessionID,
		Token:     data.NewRefreshToken.TokenHash,
		IssuedAt:  pgTz(data.NewRefreshToken.IssuedAt),
		ExpiresAt: pgTz(data.NewRefreshToken.ExpiresAt),
		CreatedIp: pgText(data.NewRefreshToken.CreatedIP),
	}); err != nil {
		return err
	}

	if err := wtx.UpdateSession(ctx, sqlc.UpdateSessionParams{
		ID:            data.Session.ID,
		LastSeenAt:    pgTzPtr(data.Session.LastSeenAt),
		MfaVerifiedAt: pgTzPtr(data.Session.MFAVerifiedAt),
		RevokedAt:     pgTzPtr(data.Session.RevokedAt),
		ExpiresAt:     pgTz(data.Session.ExpiresAt),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (p *Postgres) CreateLoginSession(ctx context.Context, data application.CreateLoginSessionData) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateLoginSession")
	defer span.End()

	tx, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		rErr := tx.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rolback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(tx)

	if err := wtx.CreateSession(ctx, sqlc.CreateSessionParams{
		ID:            data.Session.ID,
		UserID:        data.Session.UserID,
		Token:         data.Session.TokenHash,
		CreatedAt:     pgTz(data.Session.CreatedAt),
		ExpiresAt:     pgTz(data.Session.ExpiresAt),
		IpAddress:     pgText(data.Session.IPAddress),
		UserAgent:     pgText(data.Session.UserAgent),
		LastSeenAt:    pgTzPtr(data.Session.LastSeenAt),
		MfaVerifiedAt: pgTzPtr(data.Session.MFAVerifiedAt),
	}); err != nil {
		return err
	}

	if err := wtx.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		ID:        data.RefreshToken.ID,
		SessionID: data.RefreshToken.SessionID,
		Token:     data.RefreshToken.TokenHash,
		IssuedAt:  pgTz(data.RefreshToken.IssuedAt),
		ExpiresAt: pgTz(data.RefreshToken.ExpiresAt),
		CreatedIp: pgText(data.RefreshToken.CreatedIP),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (p *Postgres) CompleteMfaLogin(ctx context.Context, data application.CompleteMfaLoginData) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CompleteMfaLogin")
	defer span.End()

	tx, err := p.conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		rErr := tx.Rollback(ctx)
		if rErr != nil && !errors.Is(rErr, pgx.ErrTxClosed) {
			slog.Error("failed to rolback", "error", rErr)
		}
	}()

	wtx := p.query.WithTx(tx)

	if data.Factor != nil {
		err := wtx.UpdateMfaFactorLastUsedAt(ctx, sqlc.UpdateMfaFactorLastUsedAtParams{
			ID:         data.Factor.ID,
			LastUsedAt: pgTzPtr(data.Factor.LastUsedAt),
		})
		if err != nil {
			return err
		}
	}

	if data.BackupCode != nil {
		err := wtx.MarkBackupCodeUsed(ctx, sqlc.MarkBackupCodeUsedParams{
			ID:     data.BackupCode.ID,
			UsedAt: pgTzPtr(data.BackupCode.UsedAt),
		})
		if err != nil {
			return err
		}
	}

	if err := wtx.UpdateAuthFlow(ctx, sqlc.UpdateAuthFlowParams{
		ID:          data.Flow.ID,
		FlowState:   data.Flow.FlowState.Value(),
		CompletedAt: pgTzPtr(data.Flow.CompletedAt),
	}); err != nil {
		return err
	}

	if err := wtx.CreateSession(ctx, sqlc.CreateSessionParams{
		ID:            data.Session.ID,
		UserID:        data.Session.UserID,
		Token:         data.Session.TokenHash,
		CreatedAt:     pgTz(data.Session.CreatedAt),
		ExpiresAt:     pgTz(data.Session.ExpiresAt),
		IpAddress:     pgText(data.Session.IPAddress),
		UserAgent:     pgText(data.Session.UserAgent),
		LastSeenAt:    pgTzPtr(data.Session.LastSeenAt),
		MfaVerifiedAt: pgTzPtr(data.Session.MFAVerifiedAt),
	}); err != nil {
		return err
	}

	if err := wtx.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		ID:        data.RefreshToken.ID,
		SessionID: data.RefreshToken.SessionID,
		Token:     data.RefreshToken.TokenHash,
		IssuedAt:  pgTz(data.RefreshToken.IssuedAt),
		ExpiresAt: pgTz(data.RefreshToken.ExpiresAt),
		CreatedIp: pgText(data.RefreshToken.CreatedIP),
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (p *Postgres) CreateAuthFlow(ctx context.Context, flow domain.AuthFlow) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateAuthFlow")
	defer span.End()

	ctxJSON, err := json.Marshal(flow.Context)
	if err != nil {
		ctxJSON = []byte(`{}`)
	}

	return p.query.CreateAuthFlow(ctx, sqlc.CreateAuthFlowParams{
		ID:          flow.ID,
		UserID:      pgInt8(flow.UserID),
		FlowType:    int16(flow.FlowType),
		FlowState:   int16(flow.FlowState),
		IpAddress:   pgText(flow.IPAddress),
		UserAgent:   pgText(flow.UserAgent),
		Context:     ctxJSON,
		CreatedAt:   pgTz(flow.CreatedAt),
		ExpiresAt:   pgTz(flow.ExpiresAt),
		CompletedAt: pgTzPtr(flow.CompletedAt),
	})
}

func (p *Postgres) CreateSecurityEvent(ctx context.Context, ev domain.SecurityEvent) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateSecurityEvent")
	defer span.End()

	meta, err := json.Marshal(ev.Metadata)
	if err != nil {
		meta = []byte(`{}`)
	}

	return p.query.CreateSecurityEvent(ctx, sqlc.CreateSecurityEventParams{
		ID:        ev.ID,
		UserID:    pgInt8(ev.UserID),
		EventType: string(ev.EventType),
		IpAddress: pgText(ev.IPAddress),
		UserAgent: pgText(ev.UserAgent),
		Metadata:  meta,
		CreatedAt: pgTz(ev.CreatedAt),
	})
}

func (p *Postgres) GetUserByID(ctx context.Context, id int64) (*domain.User, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetUserByID")
	defer span.End()

	row, err := p.query.GetUserByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}

	if err != nil {
		return nil, err
	}

	return &domain.User{
		ID:        row.ID,
		Status:    domain.UserStatus(row.Status),
		Name:      row.Name,
		Username:  fromPgText(row.Username),
		AvatarURL: fromPgText(row.AvatarUrl),
		CreatedAt: row.CreatedAt.Time,
		UpdatedAt: row.UpdatedAt.Time,
		DeletedAt: fromPgTz(row.DeletedAt),
	}, nil
}

func (p *Postgres) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetUserByUsername")
	defer span.End()

	row, err := p.query.GetUserByUsername(ctx, pgText(&username))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}

	if err != nil {
		return nil, err
	}

	return &domain.User{
		ID:        row.ID,
		Status:    domain.UserStatus(row.Status),
		Name:      row.Name,
		Username:  fromPgText(row.Username),
		AvatarURL: fromPgText(row.AvatarUrl),
		CreatedAt: row.CreatedAt.Time,
		UpdatedAt: row.UpdatedAt.Time,
		DeletedAt: fromPgTz(row.DeletedAt),
	}, nil
}

func (p *Postgres) GetUserEmailByEmail(ctx context.Context, email string) (*domain.UserEmail, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetUserEmailByEmail")
	defer span.End()

	row, err := p.query.GetUserEmailByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrEmailNotFound
	}

	if err != nil {
		return nil, err
	}

	return &domain.UserEmail{
		ID:         row.ID,
		UserID:     row.UserID,
		Email:      row.Email,
		IsPrimary:  row.IsPrimary,
		CreatedAt:  row.CreatedAt.Time,
		VerifiedAt: fromPgTz(row.VerifiedAt),
		DeletedAt:  fromPgTz(row.DeletedAt),
	}, nil
}

func (p *Postgres) GetPrimaryUserEmailByUserID(ctx context.Context, userID int64) (*domain.UserEmail, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetPrimaryUserEmailByUserID")
	defer span.End()

	row, err := p.query.GetPrimaryUserEmailByUserID(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrPrimaryEmailNotFound
	}

	if err != nil {
		return nil, err
	}

	return &domain.UserEmail{
		ID:         row.ID,
		UserID:     row.UserID,
		Email:      row.Email,
		IsPrimary:  row.IsPrimary,
		CreatedAt:  row.CreatedAt.Time,
		VerifiedAt: fromPgTz(row.VerifiedAt),
		DeletedAt:  fromPgTz(row.DeletedAt),
	}, nil
}

func (p *Postgres) GetUserPhoneByPhone(ctx context.Context, phone string) (*domain.UserPhoneNumber, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetUserPhoneByPhone")
	defer span.End()

	row, err := p.query.GetUserPhoneByPhone(ctx, phone)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrPhoneNotFound
	}

	if err != nil {
		return nil, err
	}

	return &domain.UserPhoneNumber{
		ID:         row.ID,
		UserID:     row.UserID,
		Phone:      row.Phone,
		CreatedAt:  row.CreatedAt.Time,
		VerifiedAt: fromPgTz(row.VerifiedAt),
		DeletedAt:  fromPgTz(row.DeletedAt),
	}, nil
}

func (p *Postgres) GetPasswordCredentialByUserID(ctx context.Context, userID int64) (*domain.PasswordCredential, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetPasswordCredentialByUserID")
	defer span.End()

	row, err := p.query.GetPasswordCredentialByUserID(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrPasswordCredentialNotFound
	}

	if err != nil {
		return nil, err
	}

	return &domain.PasswordCredential{
		UserID:            row.UserID,
		Password:          row.Password,
		PasswordChangedAt: row.PasswordChangedAt.Time,
		CreatedAt:         row.CreatedAt.Time,
		UpdatedAt:         row.UpdatedAt.Time,
	}, nil
}

func (p *Postgres) GetSessionByID(ctx context.Context, id int64) (*domain.Session, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetSessionByID")
	defer span.End()

	row, err := p.query.GetSessionByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrSessionNotFound
	}

	if err != nil {
		return nil, err
	}

	return &domain.Session{
		ID:            row.ID,
		UserID:        row.UserID,
		TokenHash:     row.Token,
		CreatedAt:     row.CreatedAt.Time,
		ExpiresAt:     row.ExpiresAt.Time,
		LastSeenAt:    fromPgTz(row.LastSeenAt),
		RevokedAt:     fromPgTz(row.RevokedAt),
		IPAddress:     fromPgText(row.IpAddress),
		UserAgent:     fromPgText(row.UserAgent),
		MFAVerifiedAt: fromPgTz(row.MfaVerifiedAt),
	}, nil
}

func (p *Postgres) GetRefreshTokenByHash(ctx context.Context, hash []byte) (*domain.RefreshToken, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetRefreshTokenByHash")
	defer span.End()

	row, err := p.query.GetRefreshTokenByHash(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrRefreshTokenNotFound
	}

	if err != nil {
		return nil, err
	}

	return &domain.RefreshToken{
		ID:         row.ID,
		SessionID:  row.SessionID,
		TokenHash:  row.Token,
		IssuedAt:   row.IssuedAt.Time,
		ExpiresAt:  row.ExpiresAt.Time,
		RevokedAt:  fromPgTz(row.RevokedAt),
		ReplacedBy: fromPgInt8(row.ReplacedBy),
		CreatedIP:  fromPgText(row.CreatedIp),
	}, nil
}

func (p *Postgres) GetAuthFlowByID(ctx context.Context, id int64) (*domain.AuthFlow, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetAuthFlowByID")
	defer span.End()

	row, err := p.query.GetAuthFlowByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrAuthFlowNotFound
	}

	if err != nil {
		return nil, err
	}

	ctxMap := make(map[string]any)
	if len(row.Context) > 0 {
		err := json.Unmarshal(row.Context, &ctxMap)
		if err != nil {
			return nil, err
		}
	}

	return &domain.AuthFlow{
		ID:          row.ID,
		UserID:      fromPgInt8(row.UserID),
		FlowType:    domain.AuthFlowType(row.FlowType),
		FlowState:   domain.AuthFlowState(row.FlowState),
		IPAddress:   fromPgText(row.IpAddress),
		UserAgent:   fromPgText(row.UserAgent),
		Context:     ctxMap,
		CreatedAt:   row.CreatedAt.Time,
		ExpiresAt:   row.ExpiresAt.Time,
		CompletedAt: fromPgTz(row.CompletedAt),
	}, nil
}

func (p *Postgres) GetTotpFactorByFactorID(ctx context.Context, factorID int64) (*domain.TotpFactor, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetTotpFactorByFactorID")
	defer span.End()

	row, err := p.query.GetTotpFactorByFactorID(ctx, factorID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrTotpFactorNotFound
	}

	if err != nil {
		return nil, err
	}

	return &domain.TotpFactor{
		FactorID:  row.FactorID,
		Secret:    row.Secret,
		Algorithm: domain.TotpAlgorithmFrom(row.Algorithm),
		Digits:    row.Digits,
		Period:    row.Period,
		CreatedAt: row.CreatedAt.Time,
	}, nil
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
			UsedAt:    fromPgTz(r.UsedAt),
			CreatedAt: r.CreatedAt.Time,
		})
	}

	return out, nil
}

func (p *Postgres) ListMfaFactorsByUserID(ctx context.Context, userID int64, includeRevoked bool) ([]domain.MfaFactor, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ListMfaFactorsByUserID")
	defer span.End()

	var (
		rows []sqlc.MfaFactor
		err  error
	)
	if includeRevoked {
		rows, err = p.query.ListMfaFactorsByUserID(ctx, userID)
	} else {
		rows, err = p.query.ListMfaFactorsByUserIDActive(ctx, userID)
	}

	if err != nil {
		return nil, err
	}

	out := make([]domain.MfaFactor, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.MfaFactor{
			ID:         r.ID,
			UserID:     r.UserID,
			Type:       domain.MfaFactorType(r.Type),
			Name:       r.Name,
			CreatedAt:  r.CreatedAt.Time,
			VerifiedAt: fromPgTz(r.VerifiedAt),
			LastUsedAt: fromPgTz(r.LastUsedAt),
			RevokedAt:  fromPgTz(r.RevokedAt),
		})
	}

	return out, nil
}
