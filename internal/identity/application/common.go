package application

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

var rePhone = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
var reUsername = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{2,19}$`)

// securityEventFlowIDKey is the metadata key carrying the auth flow ID.
const securityEventFlowIDKey = "flow_id"

// securityEventIdentifierKey is the metadata key carrying the login identifier.
const securityEventIdentifierKey = "identifier"

// securityEventVerificationIDKey is the metadata key carrying the verification challenge ID.
const securityEventVerificationIDKey = "verification_id"

// sixDigitCodeModulus bounds generate6DigitCode to [0, 999999].
const sixDigitCodeModulus = 1_000_000

type MetaInput struct {
	IPAddress string
	UserAgent string
}

type issueToken struct {
	accessID     string
	accessToken  string
	refreshID    string
	refreshToken string
}

func (a *Application) issueTokens(ctx context.Context, userID int64) (*issueToken, error) {
	accessID := a.uuid.Generate()

	accessToken, err := a.accessJWT.Issue(accessID, jwt.NewClaims(userID))
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate access token", "error", err)

		return nil, goerror.NewServer(err)
	}

	refreshID := a.uuid.Generate()

	refreshToken, err := a.refreshJWT.Issue(refreshID, jwt.NewClaims(userID))
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate refresh token", "error", err)

		return nil, goerror.NewServer(err)
	}

	return &issueToken{
		accessID:     accessID,
		accessToken:  accessToken,
		refreshID:    refreshID,
		refreshToken: refreshToken,
	}, nil
}

func (a *Application) logSecurityEvent(
	ctx context.Context,
	userID *int64,
	eventType domain.SecurityEventType,
	meta MetaInput,
	metadata map[string]any,
) {
	a.goroutine.Go(context.WithoutCancel(ctx), func(ctx context.Context) error {
		err := a.repo.CreateSecurityEvent(ctx, domain.SecurityEvent{
			ID:        a.uid.Generate(),
			UserID:    userID,
			EventType: eventType,
			IPAddress: &meta.IPAddress,
			UserAgent: &meta.UserAgent,
			Metadata:  metadata,
			CreatedAt: a.clock.Now(),
		})
		if err != nil {
			slog.ErrorContext(ctx, "failed to create security event", "error", err)
		}

		return nil
	})
}

// verificationRateLimitKeys builds the fixed-window rate-limit keys for the
// given identifiers.
func verificationRateLimitKeys(email, phone, ipAddress string) []string {
	keys := []string{}
	if email != "" {
		keys = append(keys, registrationRequestEmailKeyPrefix+email)
	}

	if phone != "" {
		keys = append(keys, registrationRequestPhoneKeyPrefix+phone)
	}

	if ipAddress != "" {
		keys = append(keys, registrationRequestIPKeyPrefix+ipAddress)
	}

	return keys
}

// checkVerificationRateLimit throttles verification requests per identifier
// and per IP (fixed window) so the endpoints cannot be used to spam an
// identifier. Rate-limiting runs before any lookup so enumeration probes
// are throttled too.
func (a *Application) checkVerificationRateLimit(
	ctx context.Context,
	email, phone, ipAddress string,
) error {
	rateLimitMax := a.config.GetInt("modules.identity.verification.rate_limit_max")
	rateWindow := a.config.GetMinute("modules.identity.verification.rate_limit_window")

	for _, key := range verificationRateLimitKeys(email, phone, ipAddress) {
		count, err := a.cache.IncrementVerificationRequest(ctx, key, rateWindow)
		if err != nil {
			slog.ErrorContext(ctx, "failed to increment verification rate limit", "error", err)

			return goerror.NewServer(err)
		}

		if count > int64(rateLimitMax) {
			slog.WarnContext(ctx, "verification rate limit exceeded")

			return goerror.NewBusiness("too many requests", goerror.CodeTooManyRequest)
		}
	}

	return nil
}

// generate6DigitCode returns a zero-padded 6-digit numeric code.
func generate6DigitCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(sixDigitCodeModulus))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%06d", n.Int64()), nil
}
