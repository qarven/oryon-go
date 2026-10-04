package postgres

import (
	"context"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) UpdateVerificationChallenge(ctx context.Context, challenge domain.VerificationChallenge) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdateVerificationChallenge")
	defer span.End()

	return p.query.UpdateVerificationChallenge(ctx, sqlc.UpdateVerificationChallengeParams{
		ID:         challenge.ID,
		Attempts:   challenge.Attempts,
		ConsumedAt: pgTzPtr(challenge.ConsumedAt),
	})
}
