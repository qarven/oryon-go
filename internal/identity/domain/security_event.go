package domain

import "time"

type SecurityEventType string

const (
	SecurityEventTypeUnknown                    SecurityEventType = "unknown"
	SecurityEventTypeLoginSuccess               SecurityEventType = "login.success"
	SecurityEventTypeLoginFailed                SecurityEventType = "login.failed"
	SecurityEventTypeLoginMFARequired           SecurityEventType = "login.mfa_required"
	SecurityEventTypeEmailVerificationRequested SecurityEventType = "email.verification_requested"
	SecurityEventTypePhoneVerificationRequested SecurityEventType = "phone.verification_requested"
	SecurityEventTypeEmailVerified              SecurityEventType = "email.verified"
	SecurityEventTypeRegistrationRequested      SecurityEventType = "registration.requested"
	SecurityEventTypeRegistrationCompleted      SecurityEventType = "registration.completed"
	SecurityEventTypePasswordResetRequested     SecurityEventType = "password.reset_requested"
	SecurityEventTypeMFAVerificationRequested   SecurityEventType = "mfa.verification_requested"
)

type SecurityEvent struct {
	ID        int64
	UserID    *int64
	EventType SecurityEventType
	IPAddress *string
	UserAgent *string
	Metadata  map[string]any
	CreatedAt time.Time
}
