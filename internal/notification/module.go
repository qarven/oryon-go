package notification

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qarven/oryon-go/internal/notification/application"
	"github.com/qarven/oryon-go/internal/notification/presentation/mq"
	"github.com/qarven/oryon-go/internal/pkg/clock"
	"github.com/qarven/oryon-go/internal/pkg/config"
	"github.com/qarven/oryon-go/internal/pkg/goroutine"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/qarven/oryon-go/internal/pkg/mail"
	"github.com/qarven/oryon-go/internal/pkg/messaging"
	"github.com/qarven/oryon-go/internal/pkg/uid"
	"github.com/qarven/oryon-go/internal/pkg/validator"
)

type Dependency struct {
	Ctx        context.Context
	DBConn     *pgxpool.Pool
	Messaging  messaging.Messaging
	Config     config.Config
	Instrument instrument.Instrumentation
	UID        uid.NumberID
	UUID       uid.StringID
	Clock      clock.Clocker
	Goroutine  *goroutine.Manager
	Validator  validator.Validator
	Mail       mail.Mail
}

type Expose struct{}

func New(dep Dependency) (*Expose, error) {
	err := dep.Validator.Validate(dep)
	if err != nil {
		return nil, fmt.Errorf("validate dependencies module notification: %w", err)
	}

	service := application.New(application.Dependency{})

	mq.RegisterConsumer(mq.Dependency{
		Ctx:       dep.Ctx,
		Config:    dep.Config,
		Goroutine: dep.Goroutine,
		Messaging: dep.Messaging,
		Service:   service,
	})

	return &Expose{}, nil
}
