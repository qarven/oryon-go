package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) GetUserByID(ctx context.Context, id domain.ID) (*domain.User, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetUserByID")
	defer span.End()

	row, err := p.query.GetUserByID(ctx, pgUUID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}

	if err != nil {
		return nil, err
	}

	return &domain.User{
		ID:        fromPgUUID(row.ID),
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
		ID:        fromPgUUID(row.ID),
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
		ID:         fromPgUUID(row.ID),
		UserID:     fromPgUUID(row.UserID),
		Email:      row.Email,
		IsPrimary:  row.IsPrimary,
		CreatedAt:  row.CreatedAt.Time,
		VerifiedAt: fromPgTz(row.VerifiedAt),
		DeletedAt:  fromPgTz(row.DeletedAt),
	}, nil
}

func (p *Postgres) GetPrimaryUserEmailByUserID(ctx context.Context, userID domain.ID) (*domain.UserEmail, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetPrimaryUserEmailByUserID")
	defer span.End()

	row, err := p.query.GetPrimaryUserEmailByUserID(ctx, pgUUID(userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrPrimaryEmailNotFound
	}

	if err != nil {
		return nil, err
	}

	return &domain.UserEmail{
		ID:         fromPgUUID(row.ID),
		UserID:     fromPgUUID(row.UserID),
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
		ID:         fromPgUUID(row.ID),
		UserID:     fromPgUUID(row.UserID),
		Phone:      row.Phone,
		CreatedAt:  row.CreatedAt.Time,
		VerifiedAt: fromPgTz(row.VerifiedAt),
		DeletedAt:  fromPgTz(row.DeletedAt),
	}, nil
}

func (p *Postgres) GetPasswordCredentialByUserID(
	ctx context.Context,
	userID domain.ID,
) (*domain.PasswordCredential, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetPasswordCredentialByUserID")
	defer span.End()

	row, err := p.query.GetPasswordCredentialByUserID(ctx, pgUUID(userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrPasswordCredentialNotFound
	}

	if err != nil {
		return nil, err
	}

	return &domain.PasswordCredential{
		UserID:            fromPgUUID(row.UserID),
		Password:          row.Password,
		PasswordChangedAt: row.PasswordChangedAt.Time,
		CreatedAt:         row.CreatedAt.Time,
		UpdatedAt:         row.UpdatedAt.Time,
	}, nil
}

func (p *Postgres) GetSessionByID(ctx context.Context, id domain.ID) (*domain.Session, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetSessionByID")
	defer span.End()

	row, err := p.query.GetSessionByID(ctx, pgUUID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrSessionNotFound
	}

	if err != nil {
		return nil, err
	}

	return &domain.Session{
		ID:            fromPgUUID(row.ID),
		UserID:        fromPgUUID(row.UserID),
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
		ID:         fromPgUUID(row.ID),
		SessionID:  fromPgUUID(row.SessionID),
		TokenHash:  row.Token,
		IssuedAt:   row.IssuedAt.Time,
		ExpiresAt:  row.ExpiresAt.Time,
		RevokedAt:  fromPgTz(row.RevokedAt),
		ReplacedBy: fromPgUUIDPtr(row.ReplacedBy),
		CreatedIP:  fromPgText(row.CreatedIp),
	}, nil
}

func (p *Postgres) GetAuthFlowByID(ctx context.Context, id domain.ID) (*domain.AuthFlow, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetAuthFlowByID")
	defer span.End()

	row, err := p.query.GetAuthFlowByID(ctx, pgUUID(id))
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
		ID:          fromPgUUID(row.ID),
		UserID:      fromPgUUIDPtr(row.UserID),
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

func (p *Postgres) GetTotpFactorByFactorID(ctx context.Context, factorID domain.ID) (*domain.TotpFactor, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetTotpFactorByFactorID")
	defer span.End()

	row, err := p.query.GetTotpFactorByFactorID(ctx, pgUUID(factorID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrTotpFactorNotFound
	}

	if err != nil {
		return nil, err
	}

	return &domain.TotpFactor{
		FactorID:  fromPgUUID(row.FactorID),
		Secret:    row.Secret,
		Algorithm: domain.TotpAlgorithmFrom(row.Algorithm),
		Digits:    row.Digits,
		Period:    row.Period,
		CreatedAt: row.CreatedAt.Time,
	}, nil
}

func (p *Postgres) GetVerificationChallengeByID(
	ctx context.Context,
	id domain.ID,
) (*domain.VerificationChallenge, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetVerificationChallengeByID")
	defer span.End()

	row, err := p.query.GetVerificationChallengeByID(ctx, pgUUID(id))
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
		ID:          fromPgUUID(row.ID),
		UserID:      fromPgUUIDPtr(row.UserID),
		FlowID:      fromPgUUIDPtr(row.FlowID),
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
