package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) UpdateVerificationChallenge(ctx context.Context, challenge domain.VerificationChallenge) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdateVerificationChallenge")
	defer span.End()

	return p.query.UpdateVerificationChallenge(ctx, sqlc.UpdateVerificationChallengeParams{
		ID:         pgUUID(challenge.ID),
		Attempts:   challenge.Attempts,
		ConsumedAt: pgTzPtr(challenge.ConsumedAt),
	})
}

func (p *Postgres) UpdatePasskeyLogin(
	ctx context.Context,
	passkeyID domain.ID,
	signCount int64,
	lastUsedAt time.Time,
) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdatePasskeyLogin")
	defer span.End()

	return p.query.UpdatePasskeyLogin(ctx, sqlc.UpdatePasskeyLoginParams{
		ID:         pgUUID(passkeyID),
		SignCount:  signCount,
		LastUsedAt: pgTz(lastUsedAt),
	})
}

func (p *Postgres) UpdateAuthFlowContext(
	ctx context.Context,
	flowID domain.ID,
	flowCtx map[string]any,
) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdateAuthFlowContext")
	defer span.End()

	ctxJSON, err := json.Marshal(flowCtx)
	if err != nil {
		ctxJSON = []byte(`{}`)
	}

	return p.query.UpdateAuthFlowContext(ctx, sqlc.UpdateAuthFlowContextParams{
		ID:      pgUUID(flowID),
		Context: ctxJSON,
	})
}
