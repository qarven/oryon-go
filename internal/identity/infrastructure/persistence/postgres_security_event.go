package persistence

import (
	"context"
	"encoding/json"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

func (p *Postgres) CreateSecurityEvent(ctx context.Context, ev domain.SecurityEvent) error {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateSecurityEvent")
	defer span.End()

	meta, _ := json.Marshal(ev.Metadata)
	if meta == nil {
		meta = []byte(`{}`)
	}
	return p.query.CreateSecurityEvent(ctx, sqlc.CreateSecurityEventParams{
		ID:        ev.ID,
		UserID:    pgInt8(ev.UserID),
		EventType: ev.EventType,
		IpAddress: inetPtr(ev.IPAddress),
		UserAgent: pgText(ev.UserAgent),
		Metadata:  meta,
		CreatedAt: pgTimestamptz(ev.CreatedAt),
	})
}

func (p *Postgres) ListSecurityEventsByUserID(ctx context.Context, userID int64, limit, offset int32) ([]domain.SecurityEvent, int64, error) {
	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ListSecurityEventsByUserID")
	defer span.End()

	// Use sqlc for base query then paginate in Go (sqlc query doesn't have limit/offset)
	rows, err := p.query.ListSecurityEventsByUserID(ctx, pgInt8(&userID))
	if err != nil {
		return nil, 0, err
	}
	total := int64(len(rows))
	// paginate
	start := min(int(offset), len(rows))
	end := start + int(limit)
	if limit == 0 {
		end = len(rows)
	}
	if end > len(rows) {
		end = len(rows)
	}
	paged := rows[start:end]
	out := make([]domain.SecurityEvent, 0, len(paged))
	for _, r := range paged {
		var meta map[string]any
		if len(r.Metadata) > 0 {
			_ = json.Unmarshal(r.Metadata, &meta)
		}
		if meta == nil {
			meta = make(map[string]any)
		}
		out = append(out, domain.SecurityEvent{
			ID:        r.ID,
			UserID:    fromPgInt8(r.UserID),
			EventType: r.EventType,
			IPAddress: fromInetPtr(r.IpAddress),
			UserAgent: fromPgText(r.UserAgent),
			Metadata:  meta,
			CreatedAt: r.CreatedAt.Time,
		})
	}
	return out, total, nil
}
