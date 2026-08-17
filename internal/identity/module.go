package identity

import (
	"fmt"
	"net/http"

	connectrpc "connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qarven/mono/gen/go/oryon/identity/v1/identityconnect"
	"github.com/qarven/oryon-go/internal/identity/application"
	"github.com/qarven/oryon-go/internal/identity/infrastructure/cache"
	"github.com/qarven/oryon-go/internal/identity/infrastructure/persistence"
	"github.com/qarven/oryon-go/internal/identity/presentation/connect"
	"github.com/qarven/oryon-go/internal/pkg/clock"
	"github.com/qarven/oryon-go/internal/pkg/config"
	"github.com/qarven/oryon-go/internal/pkg/goroutine"
	"github.com/qarven/oryon-go/internal/pkg/hash"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
	"github.com/qarven/oryon-go/internal/pkg/uid"
	"github.com/qarven/oryon-go/internal/pkg/validator"
	"github.com/redis/go-redis/v9"
)

type Dependency struct {
	DBConn       *pgxpool.Pool              `validate:"required"`
	CacheConn    *redis.Client              `validate:"required"`
	Goroutine    *goroutine.Manager         `validate:"required"`
	Config       config.Config              `validate:"required"`
	Instrument   instrument.Instrumentation `validate:"required"`
	UID          uid.NumberID               `validate:"required"`
	UUID         uid.StringID               `validate:"required"`
	Argon2ID     hash.Hash                  `validate:"required"`
	Clock        clock.Clocker              `validate:"required"`
	Validator    validator.Validator        `validate:"required"`
	AccessJWT    jwt.JWT                    `validate:"required"`
	RefreshJWT   jwt.JWT                    `validate:"required"`
	Interceptors []connectrpc.Interceptor   `validate:"required"`
	Muxer        *http.ServeMux             `validate:"required"`
}

func New(dep Dependency) ([]string, error) {
	err := dep.Validator.Validate(dep)
	if err != nil {
		return nil, fmt.Errorf("validate dependencies: %w", err)
	}

	repository := persistence.NewPostgres(dep.DBConn, dep.Instrument)
	cacheRepo := cache.NewRedis(dep.CacheConn, dep.Instrument)

	service := application.New(application.Dependency{
		Repository:      repository,
		CacheRepository: cacheRepo,
		Validator:       dep.Validator,
		Config:          dep.Config,
		Argon2ID:        dep.Argon2ID,
		UID:             dep.UID,
		UUID:            dep.UUID,
		Clock:           dep.Clock,
		AccessJWT:       dep.AccessJWT,
		RefreshJWT:      dep.RefreshJWT,
		Instrument:      dep.Instrument,
		Goroutine:       dep.Goroutine,
	})

	serverAuth := connect.NewAuthenticationServer(service)
	serverUser := connect.NewUserServer(service)

	dep.Muxer.Handle(identityconnect.NewAuthenticationServiceHandler(
		serverAuth,
		connectrpc.WithInterceptors(dep.Interceptors...),
	))

	dep.Muxer.Handle(identityconnect.NewUserServiceHandler(
		serverUser,
		connectrpc.WithInterceptors(dep.Interceptors...),
	))

	return []string{
		identityconnect.AuthenticationServiceName,
		identityconnect.UserServiceName,
	}, nil
}
