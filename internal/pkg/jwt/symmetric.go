package jwt

import (
	"errors"
	"strconv"
	"time"

	libJWT "github.com/golang-jwt/jwt/v5"
)

// minSecretLength is the minimum HMAC secret length required by HS512.
const minSecretLength = 64

// Symmetric implements JWT signing and verification using an HMAC secret.
type Symmetric struct {
	secret    []byte
	issuer    string
	audiences []string
	ttl       time.Duration
	clock     clocker
}

// NewHS512 constructs a Symmetric JWT implementation using HS512.
func NewHS512(cfg Config) (*Symmetric, error) {
	if len(cfg.Secret) < minSecretLength {
		return nil, ErrSigningKeyTooShort
	}

	return &Symmetric{
		secret:    cfg.Secret,
		issuer:    cfg.Issuer,
		audiences: cfg.Audiences,
		ttl:       cfg.TTL,
		clock:     cfg.Clock,
	}, nil
}

// Issue creates a signed JWT for the user.
func (s *Symmetric) Issue(jti string, claim Claims) (string, error) {
	now := s.clock.Now()

	if len(s.secret) < minSecretLength {
		return "", ErrSigningKeyTooShort
	}

	token := libJWT.NewWithClaims(libJWT.SigningMethodHS512, Claims{
		RegisteredClaims: libJWT.RegisteredClaims{
			ID:        jti,
			Subject:   strconv.FormatInt(claim.UserID, 10),
			Issuer:    s.issuer,
			Audience:  s.audiences,
			IssuedAt:  libJWT.NewNumericDate(now),
			NotBefore: libJWT.NewNumericDate(now),
			ExpiresAt: libJWT.NewNumericDate(now.Add(s.ttl)),
		},
		UserID:    claim.UserID,
		UserEmail: claim.UserEmail,
	})

	signed, err := token.SignedString(s.secret)
	if err != nil {
		return "", err
	}

	return signed, nil
}

// Verify parses and validates a JWT string.
func (s *Symmetric) Verify(tokenStr string) (Claims, error) {
	var claims Claims

	if len(s.secret) < minSecretLength {
		return Claims{}, ErrSigningKeyTooShort
	}

	token, err := libJWT.ParseWithClaims(tokenStr, &claims,
		func(t *libJWT.Token) (any, error) {
			if t.Method != libJWT.SigningMethodHS512 {
				return nil, ErrInvalidSigningMethod
			}

			return s.secret, nil
		},
		libJWT.WithIssuer(s.issuer),
		libJWT.WithAudience(s.audiences...),
		libJWT.WithValidMethods([]string{libJWT.SigningMethodHS512.Alg()}),
		libJWT.WithIssuedAt(),
		libJWT.WithExpirationRequired(),
	)
	if err != nil {
		if errors.Is(err, libJWT.ErrTokenExpired) {
			return Claims{}, ErrTokenExpired
		}

		return Claims{}, err
	}

	if !token.Valid {
		return Claims{}, ErrInvalidToken
	}

	return claims, nil
}
