package connect

import (
	v1 "github.com/qarven/mono/gen/go/oryon/identity/v1"
	"github.com/qarven/oryon-go/internal/identity/domain"
)

func fromMfaFactorType(factorType domain.MfaFactorType) v1.MfaFactorType {
	var protoTyp v1.MfaFactorType

	switch factorType {
	case domain.MfaFactorTypeTOTP:
		protoTyp = v1.MfaFactorType_MFA_FACTOR_TYPE_TOTP
	case domain.MfaFactorTypeSMS:
		protoTyp = v1.MfaFactorType_MFA_FACTOR_TYPE_SMS
	case domain.MfaFactorTypeEmail:
		protoTyp = v1.MfaFactorType_MFA_FACTOR_TYPE_EMAIL
	case domain.MfaFactorTypeWebAuthn:
		protoTyp = v1.MfaFactorType_MFA_FACTOR_TYPE_WEBAUTHN
	case domain.MfaFactorTypeBackupCode:
		protoTyp = v1.MfaFactorType_MFA_FACTOR_TYPE_BACKUP_CODE
	default:
		protoTyp = v1.MfaFactorType_MFA_FACTOR_TYPE_UNSPECIFIED
	}

	return protoTyp
}

func toMfaFactorType(factorType v1.MfaFactorType) domain.MfaFactorType {
	var typ domain.MfaFactorType

	switch factorType {
	case v1.MfaFactorType_MFA_FACTOR_TYPE_TOTP:
		typ = domain.MfaFactorTypeTOTP
	case v1.MfaFactorType_MFA_FACTOR_TYPE_SMS:
		typ = domain.MfaFactorTypeSMS
	case v1.MfaFactorType_MFA_FACTOR_TYPE_EMAIL:
		typ = domain.MfaFactorTypeEmail
	case v1.MfaFactorType_MFA_FACTOR_TYPE_WEBAUTHN:
		typ = domain.MfaFactorTypeWebAuthn
	case v1.MfaFactorType_MFA_FACTOR_TYPE_BACKUP_CODE:
		typ = domain.MfaFactorTypeBackupCode
	default:
		typ = domain.MfaFactorTypeUnknown
	}

	return typ
}

func fromAuthFlowType(flowType domain.AuthFlowType) v1.AuthFlowType {
	var protoTyp v1.AuthFlowType

	switch flowType {
	case domain.AuthFlowTypeRegistration:
		protoTyp = v1.AuthFlowType_AUTH_FLOW_TYPE_REGISTRATION
	case domain.AuthFlowTypeLogin:
		protoTyp = v1.AuthFlowType_AUTH_FLOW_TYPE_LOGIN
	case domain.AuthFlowTypeRecovery:
		protoTyp = v1.AuthFlowType_AUTH_FLOW_TYPE_RECOVERY
	case domain.AuthFlowTypeStepUpMFA:
		protoTyp = v1.AuthFlowType_AUTH_FLOW_TYPE_STEP_UP_MFA
	default:
		protoTyp = v1.AuthFlowType_AUTH_FLOW_TYPE_UNSPECIFIED
	}

	return protoTyp
}

func toAuthFlowType(flowType v1.AuthFlowType) domain.AuthFlowType {
	var typ domain.AuthFlowType

	switch flowType {
	case v1.AuthFlowType_AUTH_FLOW_TYPE_REGISTRATION:
		typ = domain.AuthFlowTypeRegistration
	case v1.AuthFlowType_AUTH_FLOW_TYPE_LOGIN:
		typ = domain.AuthFlowTypeLogin
	case v1.AuthFlowType_AUTH_FLOW_TYPE_RECOVERY:
		typ = domain.AuthFlowTypeRecovery
	case v1.AuthFlowType_AUTH_FLOW_TYPE_STEP_UP_MFA:
		typ = domain.AuthFlowTypeStepUpMFA
	default:
		typ = domain.AuthFlowTypeUnknown
	}

	return typ
}

func fromUserStatus(status domain.UserStatus) v1.UserStatus {
	var protoStatus v1.UserStatus

	switch status {
	case domain.UserStatusActive:
		protoStatus = v1.UserStatus_USER_STATUS_ACTIVE
	case domain.UserStatusInactive:
		protoStatus = v1.UserStatus_USER_STATUS_INACTIVE
	case domain.UserStatusLocked:
		protoStatus = v1.UserStatus_USER_STATUS_LOCKED
	case domain.UserStatusSuspended:
		protoStatus = v1.UserStatus_USER_STATUS_SUSPENDED
	case domain.UserStatusDeleted:
		protoStatus = v1.UserStatus_USER_STATUS_DELETED
	default:
		protoStatus = v1.UserStatus_USER_STATUS_UNSPECIFIED
	}

	return protoStatus
}

func toUserStatus(status v1.UserStatus) domain.UserStatus {
	var userStatus domain.UserStatus

	switch status {
	case v1.UserStatus_USER_STATUS_ACTIVE:
		userStatus = domain.UserStatusActive
	case v1.UserStatus_USER_STATUS_INACTIVE:
		userStatus = domain.UserStatusInactive
	case v1.UserStatus_USER_STATUS_LOCKED:
		userStatus = domain.UserStatusLocked
	case v1.UserStatus_USER_STATUS_SUSPENDED:
		userStatus = domain.UserStatusSuspended
	case v1.UserStatus_USER_STATUS_DELETED:
		userStatus = domain.UserStatusDeleted
	default:
		userStatus = domain.UserStatusUnknown
	}

	return userStatus
}

func fromVerificationPurpose(purpose domain.VerificationPurpose) v1.VerificationPurpose {
	var protoPurpose v1.VerificationPurpose

	switch purpose {
	case domain.VerificationPurposeEmailVerification:
		protoPurpose = v1.VerificationPurpose_VERIFICATION_PURPOSE_EMAIL_VERIFICATION
	case domain.VerificationPurposePhoneVerification:
		protoPurpose = v1.VerificationPurpose_VERIFICATION_PURPOSE_PHONE_VERIFICATION
	case domain.VerificationPurposePasswordReset:
		protoPurpose = v1.VerificationPurpose_VERIFICATION_PURPOSE_PASSWORD_RESET
	case domain.VerificationPurposeMFAVerification:
		protoPurpose = v1.VerificationPurpose_VERIFICATION_PURPOSE_MFA_VERIFICATION
	default:
		protoPurpose = v1.VerificationPurpose_VERIFICATION_PURPOSE_UNSPECIFIED
	}

	return protoPurpose
}

func toVerificationPurpose(purpose v1.VerificationPurpose) domain.VerificationPurpose {
	var typ domain.VerificationPurpose

	switch purpose {
	case v1.VerificationPurpose_VERIFICATION_PURPOSE_EMAIL_VERIFICATION:
		typ = domain.VerificationPurposeEmailVerification
	case v1.VerificationPurpose_VERIFICATION_PURPOSE_PHONE_VERIFICATION:
		typ = domain.VerificationPurposePhoneVerification
	case v1.VerificationPurpose_VERIFICATION_PURPOSE_PASSWORD_RESET:
		typ = domain.VerificationPurposePasswordReset
	case v1.VerificationPurpose_VERIFICATION_PURPOSE_MFA_VERIFICATION:
		typ = domain.VerificationPurposeMFAVerification
	default:
		typ = domain.VerificationPurposeUnknown
	}

	return typ
}

func fromAuthFlowState(flowState domain.AuthFlowState) v1.AuthFlowState {
	var protoTyp v1.AuthFlowState

	switch flowState {
	case domain.AuthFlowStatePendingIdentifier:
		protoTyp = v1.AuthFlowState_AUTH_FLOW_STATE_PENDING_IDENTIFIER
	case domain.AuthFlowStatePendingPassword:
		protoTyp = v1.AuthFlowState_AUTH_FLOW_STATE_PENDING_PASSWORD
	case domain.AuthFlowStatePendingMFA:
		protoTyp = v1.AuthFlowState_AUTH_FLOW_STATE_PENDING_MFA
	case domain.AuthFlowStatePendingVerification:
		protoTyp = v1.AuthFlowState_AUTH_FLOW_STATE_PENDING_VERIFICATION
	case domain.AuthFlowStateCompleted:
		protoTyp = v1.AuthFlowState_AUTH_FLOW_STATE_COMPLETED
	case domain.AuthFlowStateFailed:
		protoTyp = v1.AuthFlowState_AUTH_FLOW_STATE_FAILED
	default:
		protoTyp = v1.AuthFlowState_AUTH_FLOW_STATE_UNSPECIFIED
	}

	return protoTyp
}

func toAuthFlowState(flowState v1.AuthFlowState) domain.AuthFlowState {
	var typ domain.AuthFlowState

	switch flowState {
	case v1.AuthFlowState_AUTH_FLOW_STATE_PENDING_IDENTIFIER:
		typ = domain.AuthFlowStatePendingIdentifier
	case v1.AuthFlowState_AUTH_FLOW_STATE_PENDING_PASSWORD:
		typ = domain.AuthFlowStatePendingPassword
	case v1.AuthFlowState_AUTH_FLOW_STATE_PENDING_MFA:
		typ = domain.AuthFlowStatePendingMFA
	case v1.AuthFlowState_AUTH_FLOW_STATE_PENDING_VERIFICATION:
		typ = domain.AuthFlowStatePendingVerification
	case v1.AuthFlowState_AUTH_FLOW_STATE_COMPLETED:
		typ = domain.AuthFlowStateCompleted
	case v1.AuthFlowState_AUTH_FLOW_STATE_FAILED:
		typ = domain.AuthFlowStateFailed
	default:
		typ = domain.AuthFlowStateUnknown
	}

	return typ
}
