package event

import (
	"context"
	"encoding/json"

	"github.com/qarven/oryon-go/internal/identity/application"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/qarven/oryon-go/internal/pkg/messaging"
)

const (
	identityRegistration    = "identity.registration"
	identityPasswordReset   = "identity.password_reset"
	identityMFAVerification = "identity.mfa_verification"
)

type Event struct {
	msg messaging.Messaging
	ins instrument.Instrumentation
}

func New(msg messaging.Messaging, ins instrument.Instrumentation) *Event {
	return &Event{
		msg: msg,
		ins: ins,
	}
}

func (e *Event) PublishEventRegistration(ctx context.Context, data application.EventRegistrationData) error {
	return e.publish(ctx, identityRegistration, data)
}

func (e *Event) PublishEventPasswordReset(ctx context.Context, data application.EventPasswordResetData) error {
	return e.publish(ctx, identityPasswordReset, data)
}

func (e *Event) PublishEventMFAVerification(ctx context.Context, data application.EventMFAVerificationData) error {
	return e.publish(ctx, identityMFAVerification, data)
}

func (e *Event) publish(ctx context.Context, subject string, data any) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	_, err = e.msg.Publish(ctx, subject, messaging.OutgoingMessage{
		Body: bytes,
		Headers: []messaging.Header{{
			Key:   "_correlation_id",
			Value: []byte(instrument.GetCorrelationID(ctx)),
		}},
	})

	return err
}
