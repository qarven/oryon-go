package application

import (
	"encoding/json"
	"errors"
	"math"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/qarven/oryon-go/internal/identity/domain"
)

// webauthnSessionContextKey is the auth flow context key holding the
// JSON-encoded login ceremony session between Begin and Complete.
const webauthnSessionContextKey = "webauthn_session"

// ErrWebAuthnSessionMissing indicates the auth flow carries no WebAuthn session.
var ErrWebAuthnSessionMissing = errors.New("webauthn session missing")

// errCredentialMismatch is a data integrity sentinel: the library verified a
// credential that is not in the passkey list it was given.
var errCredentialMismatch = errors.New("verified credential not in passkey list")

// webauthnUser adapts a domain user plus passkeys to the library User interface.
type webauthnUser struct {
	user     *domain.User
	passkeys []domain.Passkey
}

func (u *webauthnUser) WebAuthnID() []byte {
	return []byte(u.user.ID.String())
}

func (u *webauthnUser) WebAuthnName() string {
	if u.user.Username != nil && *u.user.Username != "" {
		return *u.user.Username
	}

	return u.user.Name
}

func (u *webauthnUser) WebAuthnDisplayName() string {
	if u.user.Name != "" {
		return u.user.Name
	}

	return u.WebAuthnName()
}

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, 0, len(u.passkeys))
	for _, passkey := range u.passkeys {
		creds = append(creds, passkeyToCredential(passkey))
	}

	return creds
}

func passkeyToCredential(passkey domain.Passkey) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(passkey.Transports))
	for _, transport := range passkey.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(transport))
	}

	var aaguid []byte

	if passkey.AAGUID != nil {
		parsed, parseErr := uuid.Parse(*passkey.AAGUID)
		if parseErr == nil {
			aaguid = parsed[:]
		}
	}

	var signCount uint32

	if passkey.SignCount > 0 {
		signCount = uint32(min(passkey.SignCount, math.MaxUint32))
	}

	return webauthn.Credential{
		ID:        passkey.CredentialID,
		PublicKey: passkey.PublicKey,
		Transport: transports,
		Authenticator: webauthn.Authenticator{
			AAGUID:    aaguid,
			SignCount: signCount,
		},
	}
}

func setWebAuthnSession(flow *domain.AuthFlow, session *webauthn.SessionData) error {
	raw, err := json.Marshal(session)
	if err != nil {
		return err
	}

	if flow.Context == nil {
		flow.Context = map[string]any{}
	}

	flow.Context[webauthnSessionContextKey] = string(raw)

	return nil
}

func webAuthnSessionFromFlow(flow *domain.AuthFlow) (*webauthn.SessionData, error) {
	if flow.Context == nil {
		return nil, ErrWebAuthnSessionMissing
	}

	raw, ok := flow.Context[webauthnSessionContextKey].(string)
	if !ok || raw == "" {
		return nil, ErrWebAuthnSessionMissing
	}

	var session webauthn.SessionData

	err := json.Unmarshal([]byte(raw), &session)
	if err != nil {
		return nil, err
	}

	return &session, nil
}
