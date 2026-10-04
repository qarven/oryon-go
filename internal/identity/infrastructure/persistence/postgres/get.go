package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

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

func (p *Postgres) GetPasswordCredentialByUserID(
	ctx context.Context,
	userID int64,
) (*domain.PasswordCredential, error) {
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
