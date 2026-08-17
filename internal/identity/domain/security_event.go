package domain

import "time"

type SecurityEvent struct {
	ID        int64
	UserID    *int64
	EventType string
	IPAddress *string
	UserAgent *string
	Metadata  map[string]any
	CreatedAt time.Time
}

func NewSecurityEvent(id int64, userID *int64, eventType string, ip, ua *string, metadata map[string]any, now time.Time) *SecurityEvent {
	if metadata == nil {
		metadata = make(map[string]any)
	}

	return &SecurityEvent{
		ID:        id,
		UserID:    userID,
		EventType: eventType,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  metadata,
		CreatedAt: now,
	}
}
