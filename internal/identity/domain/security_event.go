package domain

import "time"

type SecurityEventType string

const (
	SecurityEventTypeUnknown                  SecurityEventType = "unknown"
	SecurityEventTypeLoginSuccess             SecurityEventType = "login.success"
	SecurityEventTypeLoginFailed              SecurityEventType = "login.failed"
	SecurityEventTypeLoginMFARequired         SecurityEventType = "login.mfa_required"
	SecurityEventTypeEmailVerificationRequest SecurityEventType = "email.verification_requested"
	SecurityEventTypeEmailVerified            SecurityEventType = "email.verified"
	SecurityEventTypeRegistrationRequested    SecurityEventType = "registration.requested"
	SecurityEventTypeRegistrationCompleted    SecurityEventType = "registration.completed"
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
