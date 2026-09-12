package application

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

type MetaInput struct {
	IPAddress string
	UserAgent string
}

func (a *Application) issueTokens(ctx context.Context, userID int64) (string, string, error) {
	accessID := a.uuid.Generate()

	accessToken, err := a.accessJWT.Issue(accessID, jwt.NewClaims(userID))
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate access token", "error", err)

		return "", "", goerror.NewServer(err)
	}

	refreshID := a.uuid.Generate()

	refreshToken, err := a.refreshJWT.Issue(refreshID, jwt.NewClaims(userID))
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate refresh token", "error", err)

		return "", "", goerror.NewServer(err)
	}

	return accessToken, refreshToken, nil
}

func (a *Application) logSecurityEvent(userID *int64, eventType domain.SecurityEventType, meta MetaInput, md map[string]any) {
	a.goroutine.Go(context.Background(), func(ctx context.Context) error {
		err := a.repo.CreateSecurityEvent(ctx, domain.SecurityEvent{
			ID:        a.uid.Generate(),
			UserID:    userID,
			EventType: eventType,
			IPAddress: &meta.IPAddress,
			UserAgent: &meta.UserAgent,
			Metadata:  md,
			CreatedAt: a.clock.Now(),
		})
		if err != nil {
			slog.ErrorContext(ctx, "failed to create security event", "error", err)
		}

		return nil
	})
}

// generate6DigitCode returns a zero-padded 6-digit numeric code.
func generate6DigitCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%06d", n.Int64()), nil
}
