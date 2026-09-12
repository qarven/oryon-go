package application

import (
	"context"
	"regexp"
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

var rePhone = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
var reUsername = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{2,19}$`)

type Repository interface {
	CreateRegistrationFlow(ctx context.Context, flow domain.AuthFlow, challenges []domain.VerificationChallenge) error
	CompleteRegistration(ctx context.Context, data CompleteRegistrationData) error
	RotateRefreshToken(ctx context.Context, data RotateRefreshTokenData) error
	CreateLoginSession(ctx context.Context, data CreateLoginSessionData) error
	CompleteMfaLogin(ctx context.Context, data CompleteMfaLoginData) error

	GetUserByID(ctx context.Context, id int64) (*domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (*domain.User, error)
	GetUserEmailByEmail(ctx context.Context, email string) (*domain.UserEmail, error)
	GetPrimaryUserEmailByUserID(ctx context.Context, userID int64) (*domain.UserEmail, error)
	GetUserPhoneByPhone(ctx context.Context, phone string) (*domain.UserPhoneNumber, error)
	GetPasswordCredentialByUserID(ctx context.Context, userID int64) (*domain.PasswordCredential, error)
	GetSessionByID(ctx context.Context, id int64) (*domain.Session, error)
	GetRefreshTokenByHash(ctx context.Context, hash []byte) (*domain.RefreshToken, error)
	GetAuthFlowByID(ctx context.Context, id int64) (*domain.AuthFlow, error)
	GetTotpFactorByFactorID(ctx context.Context, factorID int64) (*domain.TotpFactor, error)

	ListMfaFactorsByUserID(ctx context.Context, userID int64, includeRevoked bool) ([]domain.MfaFactor, error)
	ListBackupCodesByUserID(ctx context.Context, userID int64) ([]domain.BackupCode, error)

	CreateAuthFlow(ctx context.Context, flow domain.AuthFlow) error
	CreateSecurityEvent(ctx context.Context, ev domain.SecurityEvent) error
	CreateVerificationChallenge(ctx context.Context, vc domain.VerificationChallenge) error
	GetVerificationChallengeByID(ctx context.Context, id int64) (*domain.VerificationChallenge, error)
	ListPendingChallengesByIdentifier(ctx context.Context, identifier string, purpose domain.VerificationPurpose) ([]domain.VerificationChallenge, error)
	UpdateVerificationChallenge(ctx context.Context, vc domain.VerificationChallenge) error
}

type CacheRepository interface {
	IncrementVerificationRequest(ctx context.Context, key string, window time.Duration) (int64, error)
	// Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// Get(ctx context.Context, key string) ([]byte, error)
	// Delete(ctx context.Context, key string) error
	// Exists(ctx context.Context, key string) (bool, error)
	// IncrWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error)
	// SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	// StorePasskeyChallenge(ctx context.Context, ch domain.PasskeyChallenge) error
	// GetPasskeyChallenge(ctx context.Context, flowID int64) (*domain.PasskeyChallenge, error)
	// DeletePasskeyChallenge(ctx context.Context, flowID int64) error
	// CheckVerificationRateLimit(ctx context.Context, identifier string) (bool, error)
	// IncrementVerificationAttempt(ctx context.Context, identifier string) error
	// ResetVerificationAttempts(ctx context.Context, identifier string) error
}

type Dependency struct {
	Repository      Repository
	CacheRepository CacheRepository
	Validator       validator.Validator
	Config          config.Config
	Argon2ID        hash.Hash
	SHA256          hash.Hash
	Bcrypt          hash.Hash
	MfaEncryption   encryption.Encryption
	UID             uid.NumberID
	UUID            uid.StringID
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
	validator     validator.Validator
	config        config.Config
	argon2id      hash.Hash
	sha256        hash.Hash
	bcrypt        hash.Hash
	mfaEncryption encryption.Encryption
	uid           uid.NumberID
	uuid          uid.StringID
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
		validator:     dep.Validator,
		argon2id:      dep.Argon2ID,
		sha256:        dep.SHA256,
		bcrypt:        dep.Bcrypt,
		mfaEncryption: dep.MfaEncryption,
		config:        dep.Config,
		uid:           dep.UID,
		uuid:          dep.UUID,
		clock:         dep.Clock,
		otp:           dep.OTP,
		accessJWT:     dep.AccessJWT,
		refreshJWT:    dep.RefreshJWT,
		ins:           dep.Instrument,
		goroutine:     dep.Goroutine,
	}
}
