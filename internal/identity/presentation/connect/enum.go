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
