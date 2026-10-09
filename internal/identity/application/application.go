package application

import (
	"context"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/clock"
	"github.com/qarven/oryon-go/internal/pkg/config"
	"github.com/qarven/oryon-go/internal/pkg/encryption"
	"github.com/qarven/oryon-go/internal/pkg/goroutine"
	"github.com/qarven/oryon-go/internal/pkg/hash"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
	"github.com/qarven/oryon-go/internal/pkg/mfa"
	"github.com/qarven/oryon-go/internal/pkg/uid"
	"github.com/qarven/oryon-go/internal/pkg/validator"
)

// TxRepository groups multi-row atomic writes.
type TxRepository interface {
	CreateRegistrationFlow(ctx context.Context, flow domain.AuthFlow, challenges []domain.VerificationChallenge) error
	CompleteRegistration(ctx context.Context, data CompleteRegistrationData) error
	ResendRegistrationCode(ctx context.Context, challenges []domain.VerificationChallenge) error
	RotateRefreshToken(ctx context.Context, data RotateRefreshTokenData) error
	RevokeSession(ctx context.Context, data RevokeSessionData) error
	CreateLoginSession(ctx context.Context, data CreateLoginSessionData) error
	CompleteMfaLogin(ctx context.Context, data CompleteMfaLoginData) error
	CreatePasswordResetChallenge(ctx context.Context, challenge domain.VerificationChallenge) error
	CompletePasswordReset(ctx context.Context, data CompletePasswordResetData) error
}

// GetUserRepository groups point lookups for single-row.
//
//nolint:interfacebloat // ignore for interface has more than 10 methods
type GetUserRepository interface {
	GetUserByID(ctx context.Context, id domain.ID) (*domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (*domain.User, error)
	GetUserEmailByEmail(ctx context.Context, email string) (*domain.UserEmail, error)
	GetUserPhoneByPhone(ctx context.Context, phone string) (*domain.UserPhoneNumber, error)
	GetPrimaryUserEmailByUserID(ctx context.Context, userID domain.ID) (*domain.UserEmail, error)
	GetPasswordCredentialByUserID(ctx context.Context, userID domain.ID) (*domain.PasswordCredential, error)
	GetSessionByID(ctx context.Context, id domain.ID) (*domain.Session, error)
	GetRefreshTokenByHash(ctx context.Context, hash []byte) (*domain.RefreshToken, error)
	GetAuthFlowByID(ctx context.Context, id domain.ID) (*domain.AuthFlow, error)
	GetTotpFactorByFactorID(ctx context.Context, factorID domain.ID) (*domain.TotpFactor, error)
	GetVerificationChallengeByID(ctx context.Context, id domain.ID) (*domain.VerificationChallenge, error)
}

// ListRepository groups collection queries. Empty results are returned as empty slices.
type ListRepository interface {
	ListMfaFactorsByUserID(ctx context.Context, userID domain.ID, includeRevoked bool) ([]domain.MfaFactor, error)
	ListBackupCodesByUserID(ctx context.Context, userID domain.ID) ([]domain.BackupCode, error)
	ListPendingChallengesByIdentifier(
		ctx context.Context,
		identifier string,
		purpose domain.VerificationPurpose,
	) ([]domain.VerificationChallenge, error)
}

// CreateRepository groups single-row, non-transactional inserts.
type CreateRepository interface {
	CreateAuthFlow(ctx context.Context, flow domain.AuthFlow) error
	CreateSecurityEvent(ctx context.Context, ev domain.SecurityEvent) error
}

// UpdateRepository groups single-row, non-transactional mutations.
type UpdateRepository interface {
	UpdateVerificationChallenge(ctx context.Context, vc domain.VerificationChallenge) error
}

type Repository interface {
	TxRepository
	GetUserRepository
	ListRepository
	CreateRepository
	UpdateRepository
}

type CacheRepository interface {
	IncrementVerificationRequest(ctx context.Context, key string, window time.Duration) (int64, error)
}

type EventRepository interface {
	PublishEventRegistration(ctx context.Context, data EventRegistrationData) error
	PublishEventPasswordReset(ctx context.Context, data EventPasswordResetData) error
}

type Dependency struct {
	Repository      Repository
	CacheRepository CacheRepository
	EventRepository EventRepository
	Validator       validator.Validator
	Config          config.Config
	Argon2ID        hash.Hash
	SHA256          hash.Hash
	MfaEncryption   encryption.Encryption
	UUID            uid.ID
	Clock           clock.Clocker
	OTP             mfa.OTP
	AccessJWT       jwt.JWT
	RefreshJWT      jwt.JWT
	Instrument      instrument.Instrumentation
	Goroutine       *goroutine.Manager
}

type Application struct {
	repo          Repository
	cache         CacheRepository
	event         EventRepository
	validator     validator.Validator
	config        config.Config
	argon2id      hash.Hash
	sha256        hash.Hash
	mfaEncryption encryption.Encryption
	uuid          uid.ID
	clock         clock.Clocker
	otp           mfa.OTP
	accessJWT     jwt.JWT
	refreshJWT    jwt.JWT
	ins           instrument.Instrumentation
	goroutine     *goroutine.Manager
}

func New(dep Dependency) *Application {
	return &Application{
		repo:          dep.Repository,
		cache:         dep.CacheRepository,
		event:         dep.EventRepository,
		validator:     dep.Validator,
		argon2id:      dep.Argon2ID,
		sha256:        dep.SHA256,
		mfaEncryption: dep.MfaEncryption,
		config:        dep.Config,
		uuid:          dep.UUID,
		clock:         dep.Clock,
		otp:           dep.OTP,
		accessJWT:     dep.AccessJWT,
		refreshJWT:    dep.RefreshJWT,
		ins:           dep.Instrument,
		goroutine:     dep.Goroutine,
	}
}
