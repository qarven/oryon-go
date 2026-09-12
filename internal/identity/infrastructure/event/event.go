package event

import (
	"context"
	"encoding/json"

	"github.com/qarven/oryon-go/internal/identity/application"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/qarven/oryon-go/internal/pkg/messaging"
)

const (
	identityRegistration = "identity.registration"
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
	bytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	_, err = e.msg.Publish(ctx, identityRegistration, messaging.OutgoingMessage{
		Body: bytes,
		Headers: []messaging.Header{{
			Key:   "_correlation_id",
			Value: []byte(instrument.GetCorrelationID(ctx)),
		}},
	})

	return err
}
