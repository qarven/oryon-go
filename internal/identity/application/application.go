package application

import (
	"context"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/clock"
	"github.com/qarven/oryon-go/internal/pkg/config"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/goroutine"
	"github.com/qarven/oryon-go/internal/pkg/hash"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
	"github.com/qarven/oryon-go/internal/pkg/uid"
	"github.com/qarven/oryon-go/internal/pkg/validator"
)

type Repository interface {
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)

	GetCredentialByUserID(ctx context.Context, uID int64, credType domain.CredentialType) (*domain.Credential, error)

	ListUsers(ctx context.Context, arg domain.ListUsersArgument) ([]domain.User, int64, error)
}

type CacheRepository interface {
	// RevokeRefreshToken blocks the refresh token identified by id until the ttl expires.
	RevokeRefreshToken(ctx context.Context, id string, ttl time.Duration) error
	// IsRefreshTokenRevoked reports whether the refresh token identified by id has been revoked.
	IsRefreshTokenRevoked(ctx context.Context, id string) (bool, error)
}

type Dependency struct {
	Repository      Repository
	CacheRepository CacheRepository
	Validator       validator.Validator
	Config          config.Config
	Argon2ID        hash.Hash
	UID             uid.NumberID
	UUID            uid.StringID
	Clock           clock.Clocker
	AccessJWT       jwt.JWT
	RefreshJWT      jwt.JWT
	Instrument      instrument.Instrumentation
	Goroutine       *goroutine.Manager
}

type Application struct {
	repo       Repository
	cache      CacheRepository
	validator  validator.Validator
	config     config.Config
	argon2id   hash.Hash
	uid        uid.NumberID
	uuid       uid.StringID
	clock      clock.Clocker
	accessJWT  jwt.JWT
	refreshJWT jwt.JWT
	ins        instrument.Instrumentation
	goroutine  *goroutine.Manager
}

func New(dep Dependency) *Application {
	return &Application{
		repo:       dep.Repository,
		cache:      dep.CacheRepository,
		validator:  dep.Validator,
		argon2id:   dep.Argon2ID,
		config:     dep.Config,
		uid:        dep.UID,
		uuid:       dep.UUID,
		clock:      dep.Clock,
		accessJWT:  dep.AccessJWT,
		refreshJWT: dep.RefreshJWT,
		ins:        dep.Instrument,
		goroutine:  dep.Goroutine,
	}
}

func (a *Application) issueTokens(userID int64, userEmail string) (string, string, error) {
	accessID := a.uuid.Generate()

	accessToken, err := a.accessJWT.Issue(accessID, jwt.NewClaims(userID, userEmail))
	if err != nil {
		return "", "", goerror.NewServer(err)
	}

	refreshID := a.uuid.Generate()

	refreshToken, err := a.refreshJWT.Issue(refreshID, jwt.NewClaims(userID, userEmail))
	if err != nil {
		return "", "", goerror.NewServer(err)
	}

	return accessToken, refreshToken, nil
}
