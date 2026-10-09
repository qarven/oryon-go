package application

import (
	"context"
	"log/slog"

	"github.com/qarven/oryon-go/internal/identity/domain"
)

// securityEventBuilder assembles a security event. The zero value is not
// usable; construct it with securityEvent and finish with Emit.
type securityEventBuilder struct {
	userID    *domain.ID
	eventType domain.SecurityEventType
	meta      MetaInput
	metadata  map[string]any
	app       *Application
}

func (a *Application) securityEvent(eventType domain.SecurityEventType) *securityEventBuilder {
	return &securityEventBuilder{eventType: eventType, app: a}
}

func (b *securityEventBuilder) ForUser(userID *domain.ID) *securityEventBuilder {
	b.userID = userID

	return b
}

func (b *securityEventBuilder) WithMeta(meta MetaInput) *securityEventBuilder {
	b.meta = meta

	return b
}

func (b *securityEventBuilder) With(key string, value any) *securityEventBuilder {
	if b.metadata == nil {
		b.metadata = map[string]any{}
	}

	b.metadata[key] = value

	return b
}

func (b *securityEventBuilder) Emit(ctx context.Context) {
	b.app.goroutine.Go(context.WithoutCancel(ctx), func(ctx context.Context) error {
		err := b.app.repo.CreateSecurityEvent(ctx, domain.SecurityEvent{
			ID:        domain.IDFrom(b.app.uuid.Generate()),
			UserID:    b.userID,
			EventType: b.eventType,
			IPAddress: &b.meta.IPAddress,
			UserAgent: &b.meta.UserAgent,
			Metadata:  b.metadata,
			CreatedAt: b.app.clock.Now(),
		})
		if err != nil {
			slog.ErrorContext(ctx, "failed to create security event", "error", err)
		}

		return nil
	})
}
