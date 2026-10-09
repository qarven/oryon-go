package postgres

import (
	"context"
	"encoding/json"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) CreateAuthFlow(ctx context.Context, flow domain.AuthFlow) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateAuthFlow")
	defer span.End()

	ctxJSON, err := json.Marshal(flow.Context)
	if err != nil {
		ctxJSON = []byte(`{}`)
	}

	return p.query.CreateAuthFlow(ctx, sqlc.CreateAuthFlowParams{
		ID:          pgUUID(flow.ID),
		UserID:      pgUUIDPtr(flow.UserID),
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

func (p *Postgres) CreateSecurityEvent(ctx context.Context, event domain.SecurityEvent) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateSecurityEvent")
	defer span.End()

	meta, err := json.Marshal(event.Metadata)
	if err != nil {
		meta = []byte(`{}`)
	}

	return p.query.CreateSecurityEvent(ctx, sqlc.CreateSecurityEventParams{
		ID:        pgUUID(event.ID),
		UserID:    pgUUIDPtr(event.UserID),
		EventType: string(event.EventType),
		IpAddress: pgText(event.IPAddress),
		UserAgent: pgText(event.UserAgent),
		Metadata:  meta,
		CreatedAt: pgTz(event.CreatedAt),
	})
}

func (p *Postgres) CreateVerificationChallenge(ctx context.Context, challenge domain.VerificationChallenge) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateVerificationChallenge")
	defer span.End()

	return p.query.CreateVerificationChallenge(ctx, sqlc.CreateVerificationChallengeParams{
		ID:          pgUUID(challenge.ID),
		UserID:      pgUUIDPtr(challenge.UserID),
		FlowID:      pgUUIDPtr(challenge.FlowID),
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
}
