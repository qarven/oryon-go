package connect

import (
	v1 "github.com/qarven/mono/gen/go/oryon/identity/v1"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func toProtoUser(u domain.User) *v1.User {
	var avatar *string
	if u.AvatarURL != nil {
		avatar = u.AvatarURL
	}

	var deleted *timestamppb.Timestamp
	if u.DeletedAt != nil {
		deleted = timestamppb.New(*u.DeletedAt)
	}

	var status v1.UserStatus
	switch u.Status {
	case domain.UserStatusActive:
		status = v1.UserStatus_USER_STATUS_ACTIVE
	case domain.UserStatusInactive:
		status = v1.UserStatus_USER_STATUS_INACTIVE
	case domain.UserStatusLocked:
		status = v1.UserStatus_USER_STATUS_LOCKED
	case domain.UserStatusSuspended:
		status = v1.UserStatus_USER_STATUS_SUSPENDED
	case domain.UserStatusDeleted:
		status = v1.UserStatus_USER_STATUS_DELETED
	default:
		status = v1.UserStatus_USER_STATUS_UNSPECIFIED
	}

	return &v1.User{
		Id:        u.ID,
		Status:    status,
		Name:      u.Name,
		AvatarUrl: avatar,
		CreatedAt: timestamppb.New(u.CreatedAt),
		UpdatedAt: timestamppb.New(u.UpdatedAt),
		DeletedAt: deleted,
	}
}

func toProtoUserEmail(e domain.UserEmail) *v1.UserEmail {
	var verified *timestamppb.Timestamp
	if e.VerifiedAt != nil {
		verified = timestamppb.New(*e.VerifiedAt)
	}

	var deleted *timestamppb.Timestamp
	if e.DeletedAt != nil {
		deleted = timestamppb.New(*e.DeletedAt)
	}

	return &v1.UserEmail{
		Id:         e.ID,
		UserId:     e.UserID,
		Email:      e.Email,
		IsPrimary:  e.IsPrimary,
		CreatedAt:  timestamppb.New(e.CreatedAt),
		VerifiedAt: verified,
		DeletedAt:  deleted,
	}
}

func toProtoUserPhone(p domain.UserPhoneNumber) *v1.UserPhoneNumber {
	var verified *timestamppb.Timestamp
	if p.VerifiedAt != nil {
		verified = timestamppb.New(*p.VerifiedAt)
	}

	var deleted *timestamppb.Timestamp
	if p.DeletedAt != nil {
		deleted = timestamppb.New(*p.DeletedAt)
	}

	return &v1.UserPhoneNumber{
		Id:         p.ID,
		UserId:     p.UserID,
		Phone:      p.Phone,
		CreatedAt:  timestamppb.New(p.CreatedAt),
		VerifiedAt: verified,
		DeletedAt:  deleted,
	}
}

func toProtoIdentity(ident domain.Identity) *v1.Identity {
	var lastUsed *timestamppb.Timestamp
	if ident.LastUsedAt != nil {
		lastUsed = timestamppb.New(*ident.LastUsedAt)
	}

	var revoked *timestamppb.Timestamp
	if ident.RevokedAt != nil {
		revoked = timestamppb.New(*ident.RevokedAt)
	}

	var prov v1.IdentityProvider
	switch ident.Provider {
	case domain.IdentityProviderGoogle:
		prov = v1.IdentityProvider_IDENTITY_PROVIDER_GOOGLE
	case domain.IdentityProviderApple:
		prov = v1.IdentityProvider_IDENTITY_PROVIDER_APPLE
	case domain.IdentityProviderGithub:
		prov = v1.IdentityProvider_IDENTITY_PROVIDER_GITHUB
	case domain.IdentityProviderFacebook:
		prov = v1.IdentityProvider_IDENTITY_PROVIDER_FACEBOOK
	case domain.IdentityProviderMicrosoft:
		prov = v1.IdentityProvider_IDENTITY_PROVIDER_MICROSOFT
	default:
		prov = v1.IdentityProvider_IDENTITY_PROVIDER_UNSPECIFIED
	}

	return &v1.Identity{
		Id:              ident.ID,
		UserId:          ident.UserID,
		Provider:        prov,
		ProviderSubject: ident.ProviderSubject,
		CreatedAt:       timestamppb.New(ident.CreatedAt),
		LastUsedAt:      lastUsed,
		RevokedAt:       revoked,
	}
}

func toProtoSession(s domain.Session, isCurrent bool) *v1.Session {
	var lastSeen *timestamppb.Timestamp
	if s.LastSeenAt != nil {
		lastSeen = timestamppb.New(*s.LastSeenAt)
	}

	var revoked *timestamppb.Timestamp
	if s.RevokedAt != nil {
		revoked = timestamppb.New(*s.RevokedAt)
	}

	var mfa *timestamppb.Timestamp
	if s.MFAVerifiedAt != nil {
		mfa = timestamppb.New(*s.MFAVerifiedAt)
	}

	var ip *string
	if s.IPAddress != nil {
		ip = s.IPAddress
	}

	var ua *string
	if s.UserAgent != nil {
		ua = s.UserAgent
	}

	return &v1.Session{
		Id:            s.ID,
		UserId:        s.UserID,
		CreatedAt:     timestamppb.New(s.CreatedAt),
		ExpiresAt:     timestamppb.New(s.ExpiresAt),
		LastSeenAt:    lastSeen,
		RevokedAt:     revoked,
		IpAddress:     ip,
		UserAgent:     ua,
		MfaVerifiedAt: mfa,
		IsCurrent:     isCurrent,
	}
}

func toProtoAuthFlow(f domain.AuthFlow) *v1.AuthFlow {
	var flowType v1.AuthFlowType
	switch f.FlowType {
	case domain.AuthFlowTypeRegistration:
		flowType = v1.AuthFlowType_AUTH_FLOW_TYPE_REGISTRATION
	case domain.AuthFlowTypeLogin:
		flowType = v1.AuthFlowType_AUTH_FLOW_TYPE_LOGIN
	case domain.AuthFlowTypeRecovery:
		flowType = v1.AuthFlowType_AUTH_FLOW_TYPE_RECOVERY
	case domain.AuthFlowTypeStepUpMFA:
		flowType = v1.AuthFlowType_AUTH_FLOW_TYPE_STEP_UP_MFA
	default:
		flowType = v1.AuthFlowType_AUTH_FLOW_TYPE_UNSPECIFIED
	}

	var flowState v1.AuthFlowState
	switch f.FlowState {
	case domain.AuthFlowStatePendingIdentifier:
		flowState = v1.AuthFlowState_AUTH_FLOW_STATE_PENDING_IDENTIFIER
	case domain.AuthFlowStatePendingPassword:
		flowState = v1.AuthFlowState_AUTH_FLOW_STATE_PENDING_PASSWORD
	case domain.AuthFlowStatePendingMFA:
		flowState = v1.AuthFlowState_AUTH_FLOW_STATE_PENDING_MFA
	case domain.AuthFlowStatePendingVerification:
		flowState = v1.AuthFlowState_AUTH_FLOW_STATE_PENDING_VERIFICATION
	case domain.AuthFlowStateCompleted:
		flowState = v1.AuthFlowState_AUTH_FLOW_STATE_COMPLETED
	case domain.AuthFlowStateFailed:
		flowState = v1.AuthFlowState_AUTH_FLOW_STATE_FAILED
	default:
		flowState = v1.AuthFlowState_AUTH_FLOW_STATE_UNSPECIFIED
	}

	return &v1.AuthFlow{
		Id:        f.ID,
		FlowType:  flowType,
		FlowState: flowState,
		ExpiresAt: timestamppb.New(f.ExpiresAt),
	}
}

func toProtoVerificationChallenge(vc domain.VerificationChallenge) *v1.VerificationChallenge {
	var uid *int64
	if vc.UserID != nil {
		uid = vc.UserID
	}

	var fid *int64
	if vc.FlowID != nil {
		fid = vc.FlowID
	}

	var ip *string
	if vc.IPAddress != nil {
		ip = vc.IPAddress
	}

	var consumed *timestamppb.Timestamp
	if vc.ConsumedAt != nil {
		consumed = timestamppb.New(*vc.ConsumedAt)
	}

	var purpose v1.VerificationPurpose
	switch vc.Purpose {
	case domain.VerificationPurposeEmailVerification:
		purpose = v1.VerificationPurpose_VERIFICATION_PURPOSE_EMAIL_VERIFICATION
	case domain.VerificationPurposePhoneVerification:
		purpose = v1.VerificationPurpose_VERIFICATION_PURPOSE_PHONE_VERIFICATION
	case domain.VerificationPurposePasswordReset:
		purpose = v1.VerificationPurpose_VERIFICATION_PURPOSE_PASSWORD_RESET
	case domain.VerificationPurposeMFAVerification:
		purpose = v1.VerificationPurpose_VERIFICATION_PURPOSE_MFA_VERIFICATION
	default:
		purpose = v1.VerificationPurpose_VERIFICATION_PURPOSE_UNSPECIFIED
	}

	return &v1.VerificationChallenge{
		Id:          vc.ID,
		UserId:      uid,
		FlowId:      fid,
		Identifier:  vc.Identifier,
		Purpose:     purpose,
		Attempts:    int32(vc.Attempts),
		MaxAttempts: int32(vc.MaxAttempts),
		IpAddress:   ip,
		ExpiresAt:   timestamppb.New(vc.ExpiresAt),
		ConsumedAt:  consumed,
		CreatedAt:   timestamppb.New(vc.CreatedAt),
	}
}

func toProtoToken(access, refresh string, expiresAt *timestamppb.Timestamp, expiresIn int64) *v1.Token {
	return &v1.Token{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		ExpiresAt:    expiresAt,
	}
}

func toProtoMfaFactor(f domain.MfaFactor) *v1.MfaFactor {
	var verified *timestamppb.Timestamp
	if f.VerifiedAt != nil {
		verified = timestamppb.New(*f.VerifiedAt)
	}

	var lastUsed *timestamppb.Timestamp
	if f.LastUsedAt != nil {
		lastUsed = timestamppb.New(*f.LastUsedAt)
	}

	var revoked *timestamppb.Timestamp
	if f.RevokedAt != nil {
		revoked = timestamppb.New(*f.RevokedAt)
	}

	var typ v1.MfaFactorType
	switch f.Type {
	case domain.MfaFactorTypeTOTP:
		typ = v1.MfaFactorType_MFA_FACTOR_TYPE_TOTP
	case domain.MfaFactorTypeSMS:
		typ = v1.MfaFactorType_MFA_FACTOR_TYPE_SMS
	case domain.MfaFactorTypeEmail:
		typ = v1.MfaFactorType_MFA_FACTOR_TYPE_EMAIL
	case domain.MfaFactorTypeWebAuthn:
		typ = v1.MfaFactorType_MFA_FACTOR_TYPE_WEBAUTHN
	case domain.MfaFactorTypeBackupCode:
		typ = v1.MfaFactorType_MFA_FACTOR_TYPE_BACKUP_CODE
	default:
		typ = v1.MfaFactorType_MFA_FACTOR_TYPE_UNSPECIFIED
	}

	return &v1.MfaFactor{
		Id:         f.ID,
		UserId:     f.UserID,
		Type:       typ,
		Name:       f.Name,
		CreatedAt:  timestamppb.New(f.CreatedAt),
		VerifiedAt: verified,
		LastUsedAt: lastUsed,
		RevokedAt:  revoked,
	}
}

func toProtoTotpFactor(t domain.TotpFactor) *v1.TotpFactor {
	var algo v1.TotpAlgorithm
	switch t.Algorithm {
	case domain.TotpAlgorithmSHA1:
		algo = v1.TotpAlgorithm_TOTP_ALGORITHM_SHA1
	case domain.TotpAlgorithmSHA256:
		algo = v1.TotpAlgorithm_TOTP_ALGORITHM_SHA256
	case domain.TotpAlgorithmSHA512:
		algo = v1.TotpAlgorithm_TOTP_ALGORITHM_SHA512
	default:
		algo = v1.TotpAlgorithm_TOTP_ALGORITHM_UNSPECIFIED
	}

	return &v1.TotpFactor{
		FactorId:  t.FactorID,
		Algorithm: algo,
		Digits:    int32(t.Digits),
		Period:    int32(t.Period),
		CreatedAt: timestamppb.New(t.CreatedAt),
	}
}

func toProtoPasskey(p domain.Passkey) *v1.Passkey {
	var aaguid *string
	if p.AAGUID != nil {
		aaguid = p.AAGUID
	}

	var deviceType *string
	if p.DeviceType != nil {
		deviceType = p.DeviceType
	}

	var lastUsed *timestamppb.Timestamp
	if p.LastUsedAt != nil {
		lastUsed = timestamppb.New(*p.LastUsedAt)
	}

	var revoked *timestamppb.Timestamp
	if p.RevokedAt != nil {
		revoked = timestamppb.New(*p.RevokedAt)
	}

	return &v1.Passkey{
		Id:           p.ID,
		UserId:       p.UserID,
		CredentialId: p.CredentialID,
		PublicKey:    p.PublicKey,
		SignCount:    p.SignCount,
		Name:         p.Name,
		Aaguid:       aaguid,
		Transports:   p.Transports,
		DeviceType:   deviceType,
		BackedUp:     p.BackedUp,
		CreatedAt:    timestamppb.New(p.CreatedAt),
		LastUsedAt:   lastUsed,
		RevokedAt:    revoked,
	}
}
