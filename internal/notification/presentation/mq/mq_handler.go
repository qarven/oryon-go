package mq

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/qarven/oryon-go/internal/notification/application"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/qarven/oryon-go/internal/pkg/instrument/logger"
	"github.com/qarven/oryon-go/internal/pkg/messaging"
)

type NotificationService interface {
	EventRegistration(ctx context.Context, input application.EventRegistrationInput) error
	EventPasswordReset(ctx context.Context, input application.EventPasswordResetInput) error
	EventMFAVerification(ctx context.Context, input application.EventMFAVerificationInput) error
}

type MQHandler struct {
	service NotificationService
	ins     instrument.Instrumentation
}

func ensureCorrelationID(ctx context.Context, msg messaging.Message) context.Context {
	for _, header := range msg.Headers() {
		if header.Key == logger.CorrelationIDKey {
			return instrument.SetCorrelationID(ctx, string(header.Value))
		}
	}

	for key, value := range msg.Attributes() {
		if key == logger.CorrelationIDKey {
			return instrument.SetCorrelationID(ctx, value)
		}
	}

	return instrument.SetCorrelationID(ctx, instrument.InvalidChainID)
}

func (h *MQHandler) RegistrationConsumer(ctx context.Context, msg messaging.Message) error {
	ctx = ensureCorrelationID(ctx, msg)

	body := msg.Body()
	slog.InfoContext(ctx, "consume: user registration notification start", "msg_body", string(body))

	var payload EventRegistrationMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		slog.ErrorContext(ctx, "failed to parse message body", "error", err)
		return nil
	}

	if err := h.service.EventRegistration(ctx, application.EventRegistrationInput{
		Name:     payload.Name,
		Identity: payload.Identity,
		Channel:  payload.Channel,
		Code:     payload.Code,
	}); err != nil {
		slog.ErrorContext(ctx, "failed to process event registration", "error", err)
		return err
	}

	slog.InfoContext(ctx, "consume: user registration notification end")

	return nil
}

func (h *MQHandler) PasswordResetConsumer(ctx context.Context, msg messaging.Message) error {
	ctx = ensureCorrelationID(ctx, msg)

	body := msg.Body()
	slog.InfoContext(ctx, "consume: password reset notification start", "msg_body", string(body))

	var payload EventPasswordResetMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		slog.ErrorContext(ctx, "failed to parse message body", "error", err)
		return nil
	}

	if err := h.service.EventPasswordReset(ctx, application.EventPasswordResetInput{
		Name:     payload.Name,
		Identity: payload.Identity,
		Channel:  payload.Channel,
		Code:     payload.Code,
	}); err != nil {
		slog.ErrorContext(ctx, "failed to process event password reset", "error", err)
		return err
	}

	slog.InfoContext(ctx, "consume: password reset notification end")

	return nil
}

func (h *MQHandler) MFAVerificationConsumer(ctx context.Context, msg messaging.Message) error {
	ctx = ensureCorrelationID(ctx, msg)

	body := msg.Body()
	slog.InfoContext(ctx, "consume: mfa verification notification start", "msg_body", string(body))

	var payload EventMFAVerificationMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		slog.ErrorContext(ctx, "failed to parse message body", "error", err)
		return nil
	}

	if err := h.service.EventMFAVerification(ctx, application.EventMFAVerificationInput{
		Name:     payload.Name,
		Identity: payload.Identity,
		Channel:  payload.Channel,
		Code:     payload.Code,
	}); err != nil {
		slog.ErrorContext(ctx, "failed to process event mfa verification", "error", err)
		return err
	}

	slog.InfoContext(ctx, "consume: mfa verification notification end")

	return nil
}
