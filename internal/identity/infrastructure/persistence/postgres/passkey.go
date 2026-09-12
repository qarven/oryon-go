package postgres

// import (
// 	"context"
// 	"errors"

// 	"github.com/jackc/pgx/v5"
// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/sqlc"
// )

// func (p *Postgres) CreatePasskey(ctx context.Context, pk domain.Passkey) error {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreatePasskey")
// 	defer span.End()

// 	return p.query.CreatePasskey(ctx, sqlc.CreatePasskeyParams{
// 		ID:           pk.ID,
// 		UserID:       pk.UserID,
// 		CredentialID: pk.CredentialID,
// 		PublicKey:    pk.PublicKey,
// 		SignCount:    pk.SignCount,
// 		Name:         pk.Name,
// 		Aaguid:       pgText(pk.AAGUID),
// 		Transports:   pk.Transports,
// 		DeviceType:   pgText(pk.DeviceType),
// 		BackedUp:     pk.BackedUp,
// 		CreatedAt:    pgTz(pk.CreatedAt),
// 		LastUsedAt:   pgTzPtr(pk.LastUsedAt),
// 		RevokedAt:    pgTzPtr(pk.RevokedAt),
// 	})
// }

// func (p *Postgres) GetPasskeyByID(ctx context.Context, id int64) (domain.Passkey, error) {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetPasskeyByID")
// 	defer span.End()

// 	row, err := p.query.GetPasskeyByID(ctx, id)
// 	if err != nil {
// 		if errors.Is(err, pgx.ErrNoRows) {
// 			return domain.Passkey{}, domain.ErrPasskeyNotFound
// 		}
// 		return domain.Passkey{}, err
// 	}
// 	return domain.Passkey{
// 		ID:           row.ID,
// 		UserID:       row.UserID,
// 		CredentialID: row.CredentialID,
// 		PublicKey:    row.PublicKey,
// 		SignCount:    row.SignCount,
// 		Name:         row.Name,
// 		AAGUID:       fromPgText(row.Aaguid),
// 		Transports:   row.Transports,
// 		DeviceType:   fromPgText(row.DeviceType),
// 		BackedUp:     row.BackedUp,
// 		CreatedAt:    row.CreatedAt.Time,
// 		LastUsedAt:   fromPgTz(row.LastUsedAt),
// 		RevokedAt:    fromPgTz(row.RevokedAt),
// 	}, nil
// }

// func (p *Postgres) GetPasskeyByCredentialID(ctx context.Context, credID []byte) (domain.Passkey, error) {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetPasskeyByCredentialID")
// 	defer span.End()

// 	row, err := p.query.GetPasskeyByCredentialID(ctx, credID)
// 	if err != nil {
// 		if errors.Is(err, pgx.ErrNoRows) {
// 			return domain.Passkey{}, domain.ErrPasskeyNotFound
// 		}
// 		return domain.Passkey{}, err
// 	}
// 	return domain.Passkey{
// 		ID:           row.ID,
// 		UserID:       row.UserID,
// 		CredentialID: row.CredentialID,
// 		PublicKey:    row.PublicKey,
// 		SignCount:    row.SignCount,
// 		Name:         row.Name,
// 		AAGUID:       fromPgText(row.Aaguid),
// 		Transports:   row.Transports,
// 		DeviceType:   fromPgText(row.DeviceType),
// 		BackedUp:     row.BackedUp,
// 		CreatedAt:    row.CreatedAt.Time,
// 		LastUsedAt:   fromPgTz(row.LastUsedAt),
// 		RevokedAt:    fromPgTz(row.RevokedAt),
// 	}, nil
// }

// func (p *Postgres) ListPasskeysByUserID(ctx context.Context, userID int64, includeRevoked bool) ([]domain.Passkey, error) {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ListPasskeysByUserID")
// 	defer span.End()

// 	var rows []sqlc.Passkey
// 	var err error
// 	if includeRevoked {
// 		rows, err = p.query.ListPasskeysByUserID(ctx, userID)
// 	} else {
// 		rows, err = p.query.ListPasskeysByUserIDActive(ctx, userID)
// 	}
// 	if err != nil {
// 		return nil, err
// 	}
// 	out := make([]domain.Passkey, 0, len(rows))
// 	for _, r := range rows {
// 		out = append(out, domain.Passkey{
// 			ID:           r.ID,
// 			UserID:       r.UserID,
// 			CredentialID: r.CredentialID,
// 			PublicKey:    r.PublicKey,
// 			SignCount:    r.SignCount,
// 			Name:         r.Name,
// 			AAGUID:       fromPgText(r.Aaguid),
// 			Transports:   r.Transports,
// 			DeviceType:   fromPgText(r.DeviceType),
// 			BackedUp:     r.BackedUp,
// 			CreatedAt:    r.CreatedAt.Time,
// 			LastUsedAt:   fromPgTz(r.LastUsedAt),
// 			RevokedAt:    fromPgTz(r.RevokedAt),
// 		})
// 	}
// 	return out, nil
// }

// func (p *Postgres) UpdatePasskey(ctx context.Context, pk domain.Passkey) error {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdatePasskey")
// 	defer span.End()

// 	return p.query.UpdatePasskey(ctx, sqlc.UpdatePasskeyParams{
// 		ID:         pk.ID,
// 		SignCount:  pk.SignCount,
// 		LastUsedAt: pgTzPtr(pk.LastUsedAt),
// 		RevokedAt:  pgTzPtr(pk.RevokedAt),
// 		Name:       pk.Name,
// 	})
// }
