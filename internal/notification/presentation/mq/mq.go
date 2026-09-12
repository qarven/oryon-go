package mq

import (
	"context"
	"log/slog"
	"slices"

	"github.com/qarven/oryon-go/internal/pkg/config"
	"github.com/qarven/oryon-go/internal/pkg/goroutine"
	"github.com/qarven/oryon-go/internal/pkg/messaging"
)

type Dependency struct {
	Ctx       context.Context
	Config    config.Config
	Goroutine *goroutine.Manager
	Messaging messaging.Messaging
	Service   NotificationService
}

func RegisterConsumer(dep Dependency) {
	mqHandler := &MQHandler{service: dep.Service}

	consumerNames := dep.Config.GetArray("modules.notification.consumers")

	var jobs = []struct {
		source       string
		consumerName string
		handler      messaging.Handler
	}{
		{
			source:       identityRegistrationSource,
			consumerName: identityRegistrationConsumer,
			handler:      mqHandler.RegistrationConsumer,
		},
		{
			source:       identityPasswordResetSource,
			consumerName: identityPasswordResetConsumer,
			handler:      mqHandler.PasswordResetConsumer,
		},
		{
			source:       identityMFAVerificationSource,
			consumerName: identityMFAVerificationConsumer,
			handler:      mqHandler.MFAVerificationConsumer,
		},
	}

	for _, job := range jobs {
		if len(consumerNames) > 0 && slices.Contains(consumerNames, job.consumerName) {
			dep.Goroutine.Go(dep.Ctx, func(ctx context.Context) error {
				slog.InfoContext(ctx, "Running job for handling consumer", "consumer", job.consumerName)

				return dep.Messaging.Consume(ctx, job.source, job.handler,
					messaging.WithQueueGroup(job.consumerName),
					messaging.WithAutoAck(true),
					messaging.WithConcurrency(10),
					messaging.WithMaxInFlight(10),
				)
			})
		}
	}
}
