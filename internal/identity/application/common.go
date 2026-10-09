package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"strings"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
)

var rePhone = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
var reUsername = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{2,19}$`)

var ErrRegistrationDataMissing = errors.New("registration data missing")

// sixDigitCodeModulus bounds generate6DigitCode to [0, 999999].
const sixDigitCodeModulus = 1_000_000
const sixteenDigitCodeModulus = 16

const (
	registrationRequestEmailKeyPrefix = "registration:req:email:"
	registrationRequestPhoneKeyPrefix = "registration:req:phone:"
	registrationRequestIPKeyPrefix    = "registration:req:ip:"
)

const (
	channelEmail = "email"
	channelPhone = "phone"
)

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

type pendingRegistration struct {
	Name         string
	Email        string
	Phone        string
	PasswordHash string
}

func (a *Application) issueTokens(ctx context.Context, userID domain.ID) (*issueToken, error) {
	accessID := a.uuid.Generate()

	accessToken, err := a.accessJWT.Issue(accessID, jwt.NewClaims(userID.String()))
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate access token", "error", err)

		return nil, goerror.NewServer(err)
	}

	refreshID := a.uuid.Generate()

	refreshToken, err := a.refreshJWT.Issue(refreshID, jwt.NewClaims(userID.String()))
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

func (a *Application) checkVerificationRateLimit(
	ctx context.Context,
	email, phone, ipAddress string,
) error {
	rateLimitMax := a.config.GetInt("modules.identity.verification.rate_limit_max")
	rateWindow := a.config.GetMinute("modules.identity.verification.rate_limit_window")

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

	for _, key := range keys {
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

func (a *Application) pendingRegistrationFromFlow(flow *domain.AuthFlow) (pendingRegistration, error) {
	if flow.Context == nil {
		return pendingRegistration{}, ErrRegistrationDataMissing
	}

	get := func(key string) string {
		value, ok := flow.Context[key].(string)
		if !ok {
			return ""
		}

		return strings.TrimSpace(value)
	}

	out := pendingRegistration{
		Name:         get(regCtxName),
		Email:        strings.ToLower(get(regCtxEmail)),
		Phone:        get(regCtxPhone),
		PasswordHash: get(regCtxPasswordHash),
	}

	if out.Name == "" || out.PasswordHash == "" {
		return pendingRegistration{}, ErrRegistrationDataMissing
	}

	if out.Email == "" && out.Phone == "" {
		return pendingRegistration{}, ErrRegistrationDataMissing
	}

	return out, nil
}

func generate6DigitCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(sixDigitCodeModulus))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%06d", n.Int64()), nil
}

func generate32RandomString() (string, error) {
	bytes := make([]byte, sixteenDigitCodeModulus)

	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}
