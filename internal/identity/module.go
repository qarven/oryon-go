package identity

import (
	"encoding/base64"
	"fmt"
	"net/http"

	connectrpc "connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"
	otpLib "github.com/pquerna/otp"
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
	redisLib "github.com/redis/go-redis/v9"
)

type Dependency struct {
	DBConn       *pgxpool.Pool              `validate:"required"`
	CacheConn    *redisLib.Client           `validate:"required"`
	Messaging    messaging.Messaging        `validate:"required"`
	Goroutine    *goroutine.Manager         `validate:"required"`
	Config       config.Config              `validate:"required"`
	Instrument   instrument.Instrumentation `validate:"required"`
	UID          uid.NumberID               `validate:"required"`
	UUID         uid.StringID               `validate:"required"`
	Clock        clock.Clocker              `validate:"required"`
	Validator    validator.Validator        `validate:"required"`
	Interceptors []connectrpc.Interceptor   `validate:"required"`
	Muxer        *http.ServeMux             `validate:"required"`
}

type Expose struct {
	ServiceNames []string
}

func New(dep Dependency) (*Expose, error) {
	err := dep.Validator.Validate(dep)
	if err != nil {
		return nil, fmt.Errorf("validate dependencies module identity: %w", err)
	}

	argon2id := hash.NewArgon2id(dep.Config.GetString("modules.identity.hash.argon2id.pepper"))
	sha256 := hash.NewHMACSHA256(dep.Config.GetString("modules.identity.hash.hmac.secret"))
	bcryptHash := hash.NewBcrypt(
		dep.Config.GetInt("modules.identity.hash.bcrypt.cost"),
		dep.Config.GetString("modules.identity.hash.bcrypt.pepper"),
	)

	mfaRawSecret, err := base64.StdEncoding.DecodeString(dep.Config.GetString("modules.identity.mfa.secret"))
	if err != nil {
		return nil, fmt.Errorf("decode mfa secret: %w", err)
	}

	if len(mfaRawSecret) != 32 { // secret must be 32 bytes (AES-256)
		return nil, fmt.Errorf("mfa secret must be 32 bytes, got %d", len(mfaRawSecret))
	}

	mfaEncryption, err := encryption.NewAES256Encryptor(mfaRawSecret)
	if err != nil {
		return nil, fmt.Errorf("create mfa encryptor: %w", err)
	}

	mfaTotp := mfa.NewTOTP(
		dep.Config.GetString("mfa.totp.issuer"),
		dep.Config.GetUint("mfa.totp.period"),
		dep.Config.GetUint("mfa.totp.skew"),
		otpLib.DigitsSix,
	)

	accessJWT, err := jwt.NewHS512(jwt.Config{
		Secret:    []byte(dep.Config.GetString("modules.identity.jwt.access.secret")),
		Issuer:    dep.Config.GetString("modules.identity.jwt.access.issuer"),
		Audiences: dep.Config.GetArray("modules.identity.jwt.access.audiences"),
		TTL:       dep.Config.GetMinute("modules.identity.jwt.access.ttl"),
		Clock:     dep.Clock,
	})
	if err != nil {
		return nil, err
	}

	refreshJWT, err := jwt.NewHS512(jwt.Config{
		Secret:    []byte(dep.Config.GetString("modules.identity.jwt.refresh.secret")),
		Issuer:    dep.Config.GetString("modules.identity.jwt.refresh.issuer"),
		Audiences: dep.Config.GetArray("modules.identity.jwt.refresh.audiences"),
		TTL:       dep.Config.GetDay("modules.identity.jwt.refresh.ttl"),
		Clock:     dep.Clock,
	})
	if err != nil {
		return nil, err
	}

	repository := postgres.New(dep.DBConn, dep.Instrument)
	cacheRepo := redis.New(dep.CacheConn, dep.Instrument)
	eventRepo := event.New(dep.Messaging, dep.Instrument)

	service := application.New(application.Dependency{
		Repository:      repository,
		CacheRepository: cacheRepo,
		EventRepository: eventRepo,
		Validator:       dep.Validator,
		Config:          dep.Config,
		Argon2ID:        argon2id,
		SHA256:          sha256,
		Bcrypt:          bcryptHash,
		MfaEncryption:   mfaEncryption,
		UID:             dep.UID,
		UUID:            dep.UUID,
		OTP:             mfaTotp,
		Clock:           dep.Clock,
		AccessJWT:       accessJWT,
		RefreshJWT:      refreshJWT,
		Instrument:      dep.Instrument,
		Goroutine:       dep.Goroutine,
	})

	serverAuth := connect.NewAuthenticationServer(service, dep.Config)

	dep.Muxer.Handle(identityconnect.NewAuthenticationServiceHandler(
		serverAuth,
		connectrpc.WithInterceptors(dep.Interceptors...),
	))

	return &Expose{
		ServiceNames: []string{
			identityconnect.AuthenticationServiceName,
		},
	}, nil
}
