package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/clock"
	"github.com/qarven/oryon-go/internal/pkg/config"
	"github.com/qarven/oryon-go/internal/pkg/encryption"
	"github.com/qarven/oryon-go/internal/pkg/goerror"
	"github.com/qarven/oryon-go/internal/pkg/goroutine"
	"github.com/qarven/oryon-go/internal/pkg/hash"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
	"github.com/qarven/oryon-go/internal/pkg/uid"
	"github.com/qarven/oryon-go/internal/pkg/validator"
)

type Repository interface {
	// user
	CreateUser(ctx context.Context, user domain.User) error
	GetUserByID(ctx context.Context, id int64) (domain.User, error)
	UpdateUser(ctx context.Context, user domain.User) error
	// user email
	CreateUserEmail(ctx context.Context, email domain.UserEmail) error
	GetUserEmailByID(ctx context.Context, id int64) (domain.UserEmail, error)
	GetUserEmailByEmail(ctx context.Context, email string) (domain.UserEmail, error)
	GetPrimaryUserEmailByUserID(ctx context.Context, userID int64) (domain.UserEmail, error)
	ListUserEmailsByUserID(ctx context.Context, userID int64, includeDeleted bool) ([]domain.UserEmail, error)
	UpdateUserEmail(ctx context.Context, email domain.UserEmail) error
	SetPrimaryEmailTx(ctx context.Context, userID, emailID int64) error
	CountUserEmails(ctx context.Context, userID int64) (int, error)
	// phone
	CreateUserPhoneNumber(ctx context.Context, ph domain.UserPhoneNumber) error
	GetUserPhoneByPhone(ctx context.Context, phone string) (domain.UserPhoneNumber, error)
	ListPhonesByUserID(ctx context.Context, userID int64) ([]domain.UserPhoneNumber, error)
	GetUserPhoneByID(ctx context.Context, id int64) (domain.UserPhoneNumber, error)
	// password
	CreatePasswordCredential(ctx context.Context, cred domain.PasswordCredential) error
	GetPasswordCredentialByUserID(ctx context.Context, userID int64) (domain.PasswordCredential, error)
	UpdatePasswordCredential(ctx context.Context, cred domain.PasswordCredential) error
	UpsertPasswordCredential(ctx context.Context, cred domain.PasswordCredential) error
	// legacy shim
	GetIdentityByEmail(ctx context.Context, email string) (domain.Identity, error)
	GetIdentityByID(ctx context.Context, id int64) (domain.Identity, error)
	GetIdentityCredentialByIdentityID(ctx context.Context, identityID int64, typ domain.IdentityCredentialType) (domain.IdentityCredential, error)
	// federated identities
	CreateIdentity(ctx context.Context, ident domain.Identity) error
	GetIdentityByProviderSubject(ctx context.Context, provider domain.IdentityProvider, subject string) (domain.Identity, error)
	ListIdentitiesByUserID(ctx context.Context, userID int64) ([]domain.Identity, error)
	// auth flow
	CreateAuthFlow(ctx context.Context, flow domain.AuthFlow) error
	GetAuthFlowByID(ctx context.Context, id int64) (domain.AuthFlow, error)
	UpdateAuthFlow(ctx context.Context, flow domain.AuthFlow) error
	// session
	CreateSession(ctx context.Context, sess domain.Session) error
	GetSessionByID(ctx context.Context, id int64) (domain.Session, error)
	GetSessionByTokenHash(ctx context.Context, hash []byte) (domain.Session, error)
	ListSessionsByUserID(ctx context.Context, userID int64, includeRevoked, includeExpired bool) ([]domain.Session, error)
	UpdateSession(ctx context.Context, sess domain.Session) error
	RevokeSession(ctx context.Context, id int64, at pgtype.Timestamptz) error
	RevokeAllOtherSessions(ctx context.Context, userID, currentSessionID int64, at pgtype.Timestamptz) (int64, error)
	TouchSession(ctx context.Context, id int64, at pgtype.Timestamptz) error
	// refresh token
	CreateRefreshToken(ctx context.Context, rt domain.RefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, hash []byte) (domain.RefreshToken, error)
	GetRefreshTokenByID(ctx context.Context, id int64) (domain.RefreshToken, error)
	UpdateRefreshToken(ctx context.Context, rt domain.RefreshToken) error
	RevokeRefreshTokensBySessionID(ctx context.Context, sessionID int64, at pgtype.Timestamptz) (int64, error)
	// mfa
	CreateMfaFactor(ctx context.Context, factor domain.MfaFactor) error
	GetMfaFactorByID(ctx context.Context, id int64) (domain.MfaFactor, error)
	ListMfaFactorsByUserID(ctx context.Context, userID int64, includeRevoked bool) ([]domain.MfaFactor, error)
	UpdateMfaFactor(ctx context.Context, factor domain.MfaFactor) error
	// totp
	CreateTotpFactor(ctx context.Context, totp domain.TotpFactor) error
	GetTotpFactorByFactorID(ctx context.Context, factorID int64) (domain.TotpFactor, error)
	UpdateTotpSecret(ctx context.Context, factorID int64, secret []byte) error
	DeleteTotpFactor(ctx context.Context, factorID int64) error
	// backup codes
	CreateBackupCodes(ctx context.Context, codes []domain.BackupCode) error
	ListBackupCodesByUserID(ctx context.Context, userID int64) ([]domain.BackupCode, error)
	CountUnusedBackupCodes(ctx context.Context, userID int64) (int32, error)
	DeleteBackupCodesByUserID(ctx context.Context, userID int64) (int64, error)
	FindUnusedBackupCodeByHash(ctx context.Context, userID int64, hash []byte) (domain.BackupCode, error)
	MarkBackupCodeUsed(ctx context.Context, id int64, at pgtype.Timestamptz) error
	GetBackupCodesForVerification(ctx context.Context, userID int64) ([]domain.BackupCode, error)
	// passkey
	CreatePasskey(ctx context.Context, pk domain.Passkey) error
	GetPasskeyByID(ctx context.Context, id int64) (domain.Passkey, error)
	GetPasskeyByCredentialID(ctx context.Context, credID []byte) (domain.Passkey, error)
	ListPasskeysByUserID(ctx context.Context, userID int64, includeRevoked bool) ([]domain.Passkey, error)
	UpdatePasskey(ctx context.Context, pk domain.Passkey) error
	// verification
	CreateVerificationChallenge(ctx context.Context, vc domain.VerificationChallenge) error
	GetVerificationChallengeByID(ctx context.Context, id int64) (domain.VerificationChallenge, error)
	GetVerificationByIdentifierPurpose(ctx context.Context, identifier string, purpose domain.VerificationPurpose) ([]domain.VerificationChallenge, error)
	GetVerificationChallengeByHash(ctx context.Context, hash []byte, purpose domain.VerificationPurpose) (domain.VerificationChallenge, error)
	UpdateVerificationChallenge(ctx context.Context, vc domain.VerificationChallenge) error
	IncrementVerificationAttempts(ctx context.Context, id int64) error
	ConsumeVerificationChallenge(ctx context.Context, id int64, at pgtype.Timestamptz) error
	// security events
	CreateSecurityEvent(ctx context.Context, ev domain.SecurityEvent) error
}

type CacheRepository interface {
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	IncrWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error)
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	StorePasskeyChallenge(ctx context.Context, ch domain.PasskeyChallenge) error
	GetPasskeyChallenge(ctx context.Context, flowID int64) (*domain.PasskeyChallenge, error)
	DeletePasskeyChallenge(ctx context.Context, flowID int64) error
	CheckVerificationRateLimit(ctx context.Context, identifier string) (bool, error)
	IncrementVerificationAttempt(ctx context.Context, identifier string) error
	ResetVerificationAttempts(ctx context.Context, identifier string) error
}

type Dependency struct {
	Repository      Repository
	CacheRepository CacheRepository
	Validator       validator.Validator
	Config          config.Config
	Argon2ID        hash.Hash
	MfaEncryption   encryption.Encryption
	UID             uid.NumberID
	UUID            uid.StringID
	Clock           clock.Clocker
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
	mfaEncryption encryption.Encryption
	uid           uid.NumberID
	uuid          uid.StringID
	clock         clock.Clocker
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
		mfaEncryption: dep.MfaEncryption,
		config:        dep.Config,
		uid:           dep.UID,
		uuid:          dep.UUID,
		clock:         dep.Clock,
		accessJWT:     dep.AccessJWT,
		refreshJWT:    dep.RefreshJWT,
		ins:           dep.Instrument,
		goroutine:     dep.Goroutine,
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

func (a *Application) issueTokensWithSession(userID int64, userEmail string, sessionID int64) (string, string, error) {
	// For now sessionID is not embedded in JWT claims; kept for future
	return a.issueTokens(userID, userEmail)
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func hashSHA256Hex(s string) []byte {
	h := sha256.Sum256([]byte(s))
	dst := make([]byte, hex.EncodedLen(len(h)))
	hex.Encode(dst, h[:])
	return dst
}

func hashSHA256Raw(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func generateSecureToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	// base32 without padding for shorter URL-safe string, then lower
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	s := enc.EncodeToString(b)
	s = strings.ToLower(s)
	// also hex fallback for readability
	return s, nil
}

func generateBackupCode() (string, error) {
	// 8 char alphanumeric (excluding confusing chars)
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	for i, v := range b {
		b[i] = chars[int(v)%len(chars)]
	}

	// format as XXXX-XXXX
	return fmt.Sprintf("%s-%s", string(b[:4]), string(b[4:])), nil
}

func toPgTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func toPgTimestamptzPtr(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{Valid: false}
	}

	return pgtype.Timestamptz{Time: *t, Valid: true}
}

func parseBearerToken(ctx context.Context) (string, error) {
	// This helper is used in presentation layer; kept here for reuse if needed
	_ = ctx
	return "", nil
}

func (a *Application) logSecurityEvent(ctx context.Context, userID *int64, eventType string, ip, ua *string, metadata map[string]any) {
	if a.goroutine == nil {
		return
	}

	a.goroutine.Go(context.Background(), func(ctx context.Context) error {
		ev := domain.NewSecurityEvent(a.uid.Generate(), userID, eventType, ip, ua, metadata, a.clock.Now())
		_ = a.repo.CreateSecurityEvent(ctx, *ev)
		return nil
	})
}

func (a *Application) getPrimaryEmail(ctx context.Context, userID int64) (string, error) {
	pe, err := a.repo.GetPrimaryUserEmailByUserID(ctx, userID)
	if err != nil {
		return "", err
	}

	return pe.Email, nil
}

func isValidEmail(email string) bool {
	// simple check, validator does thorough
	return strings.Contains(email, "@")
}
