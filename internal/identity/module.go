package identity

import (
	"encoding/base64"
	"errors"
	"fmt"

	connectv2 "connectrpc.com/connect/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	pquernaotp "github.com/pquerna/otp"
	"github.com/qarven/mono/gen/go/oryon/identity/v1/identityconnect"
	"github.com/qarven/oryon-go/internal/identity/application"
	"github.com/qarven/oryon-go/internal/identity/infrastructure/cache/redis"
	"github.com/qarven/oryon-go/internal/identity/infrastructure/event"
	"github.com/qarven/oryon-go/internal/identity/infrastructure/persistence/postgres"
	"github.com/qarven/oryon-go/internal/identity/presentation/connect"
	"github.com/qarven/oryon-go/internal/pkg/clock"
	"github.com/qarven/oryon-go/internal/pkg/config"
	"github.com/qarven/oryon-go/internal/pkg/encryption"
	"github.com/qarven/oryon-go/internal/pkg/goroutine"
	"github.com/qarven/oryon-go/internal/pkg/hash"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
	"github.com/qarven/oryon-go/internal/pkg/messaging"
	"github.com/qarven/oryon-go/internal/pkg/mfa"
	"github.com/qarven/oryon-go/internal/pkg/uid"
	"github.com/qarven/oryon-go/internal/pkg/validator"
	goredisv9 "github.com/redis/go-redis/v9"
)

type Dependency struct {
	DBConn     *pgxpool.Pool              `validate:"required"`
	CacheConn  *goredisv9.Client          `validate:"required"`
	Messaging  messaging.Messaging        `validate:"required"`
	Goroutine  *goroutine.Manager         `validate:"required"`
	Config     config.Config              `validate:"required"`
	Instrument instrument.Instrumentation `validate:"required"`
	UUID       uid.ID                     `validate:"required"`
	Clock      clock.Clocker              `validate:"required"`
	Validator  validator.Validator        `validate:"required"`
	Server     *connectv2.Server          `validate:"required"`
}

type Expose struct {
	ServiceNames []string
}

// mfaSecretLength is the required raw MFA secret size in bytes (AES-256).
const mfaSecretLength = 32

// ErrInvalidMFASecretLength is returned when the configured MFA secret
// has an unexpected size.
var ErrInvalidMFASecretLength = errors.New("mfa secret must be 32 bytes")

func New(dep Dependency) (*Expose, error) {
	err := dep.Validator.Validate(dep)
	if err != nil {
		return nil, fmt.Errorf("validate dependencies module identity: %w", err)
	}

	// initiate dependencies
	hashers := newHashers(dep.Config)

	mfaParts, err := newMFAComponents(dep.Config)
	if err != nil {
		return nil, err
	}

	tokens, err := newTokenPair(dep.Config, dep.Clock)
	if err != nil {
		return nil, err
	}

	webauthn, err := newWebAuthn(dep.Config)
	if err != nil {
		return nil, err
	}

	// infrastructure
	repository := postgres.New(dep.DBConn, dep.Instrument)
	cacheRepo := redis.New(dep.CacheConn, dep.Instrument)
	eventRepo := event.New(dep.Messaging, dep.Instrument)

	// application
	service := application.New(application.Dependency{
		Repository:      repository,
		CacheRepository: cacheRepo,
		EventRepository: eventRepo,
		Validator:       dep.Validator,
		Config:          dep.Config,
		Argon2ID:        hashers.argon2id,
		SHA256:          hashers.sha256,
		MfaEncryption:   mfaParts.encryption,
		UUID:            dep.UUID,
		OTP:             mfaParts.totp,
		WebAuthn:        webauthn,
		Clock:           dep.Clock,
		AccessJWT:       tokens.access,
		RefreshJWT:      tokens.refresh,
		Instrument:      dep.Instrument,
		Goroutine:       dep.Goroutine,
	})

	// presentation
	serverAuth := connect.NewAuthenticationServer(service)
	serverSession := connect.NewSessionServer(service, dep.Config)

	identityconnect.RegisterAuthenticationServiceHandler(dep.Server, serverAuth)
	identityconnect.RegisterSessionServiceHandler(dep.Server, serverSession)

	return &Expose{ServiceNames: []string{
		identityconnect.AuthenticationServiceName,
		identityconnect.SessionServiceName,
	}}, nil
}

type passwordHashers struct {
	argon2id hash.Hash
	sha256   hash.Hash
}

func newHashers(cfg config.Config) passwordHashers {
	return passwordHashers{
		argon2id: hash.NewArgon2id(cfg.GetString("modules.identity.hash.argon2id.pepper")),
		sha256:   hash.NewHMACSHA256(cfg.GetString("modules.identity.hash.hmac.secret")),
	}
}

type mfaParts struct {
	encryption encryption.Encryption
	totp       mfa.OTP
}

func newMFAComponents(cfg config.Config) (*mfaParts, error) {
	mfaRawSecret, err := base64.StdEncoding.DecodeString(cfg.GetString("modules.identity.mfa.secret"))
	if err != nil {
		return nil, fmt.Errorf("decode mfa secret: %w", err)
	}

	if len(mfaRawSecret) != mfaSecretLength {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidMFASecretLength, len(mfaRawSecret))
	}

	mfaEncryption, err := encryption.NewAES256Encryptor(mfaRawSecret)
	if err != nil {
		return nil, fmt.Errorf("create mfa encryptor: %w", err)
	}

	mfaTotp := mfa.NewTOTP(
		cfg.GetString("mfa.totp.issuer"),
		cfg.GetUint("mfa.totp.period"),
		cfg.GetUint("mfa.totp.skew"),
		pquernaotp.DigitsSix,
	)

	return &mfaParts{encryption: mfaEncryption, totp: mfaTotp}, nil
}

type tokenPair struct {
	access  jwt.JWT
	refresh jwt.JWT
}

func newTokenPair(cfg config.Config, clk clock.Clocker) (*tokenPair, error) {
	accessJWT, err := jwt.NewHS512(jwt.Config{
		Secret:    []byte(cfg.GetString("modules.identity.jwt.access.secret")),
		Issuer:    cfg.GetString("modules.identity.jwt.access.issuer"),
		Audiences: cfg.GetArray("modules.identity.jwt.access.audiences"),
		TTL:       cfg.GetMinute("modules.identity.jwt.access.ttl"),
		Clock:     clk,
	})
	if err != nil {
		return nil, err
	}

	refreshJWT, err := jwt.NewHS512(jwt.Config{
		Secret:    []byte(cfg.GetString("modules.identity.jwt.refresh.secret")),
		Issuer:    cfg.GetString("modules.identity.jwt.refresh.issuer"),
		Audiences: cfg.GetArray("modules.identity.jwt.refresh.audiences"),
		TTL:       cfg.GetDay("modules.identity.jwt.refresh.ttl"),
		Clock:     clk,
	})
	if err != nil {
		return nil, err
	}

	return &tokenPair{access: accessJWT, refresh: refreshJWT}, nil
}

func newWebAuthn(cfg config.Config) (*webauthn.WebAuthn, error) {
	authn, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.GetString("modules.identity.webauthn.rp_id"),
		RPDisplayName: cfg.GetString("modules.identity.webauthn.rp_display_name"),
		RPOrigins:     cfg.GetArray("modules.identity.webauthn.rp_origins"),
	})
	if err != nil {
		return nil, fmt.Errorf("create webauthn: %w", err)
	}

	return authn, nil
}
