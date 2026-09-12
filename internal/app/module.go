package app

import (
	"log/slog"
	"os"

	"github.com/qarven/oryon-go/internal/identity"
	"github.com/qarven/oryon-go/internal/notification"
)

func (a *App) initModules() {
	if a.config.GetBool("modules.identity.enabled") {
		expose, err := identity.New(identity.Dependency{
			Config:       a.config,
			Instrument:   a.ins,
			UID:          a.uid,
			UUID:         a.uuid,
			Clock:        a.clock,
			Validator:    a.validator,
			DBConn:       a.dbConn,
			CacheConn:    a.cacheConn,
			Messaging:    a.messaging,
			Goroutine:    a.goroutine,
			Interceptors: a.interceptors,
			Muxer:        a.muxer,
		})
		if err != nil {
			slog.Error("failed to init module identity", "error", err)
			os.Exit(1)
		}

		a.connectServiceNames = append(a.connectServiceNames, expose.ServiceNames...)
	}

	if a.config.GetBool("modules.notification.enabled") {
		_, err := notification.New(notification.Dependency{
			Ctx:        a.ctx,
			DBConn:     a.dbConn,
			Messaging:  a.messaging,
			Config:     a.config,
			Instrument: a.ins,
			UID:        a.uid,
			UUID:       a.uuid,
			Clock:      a.clock,
			Goroutine:  a.goroutine,
			Validator:  a.validator,
			Mail:       a.mail,
		})
		if err != nil {
			slog.Error("failed to init module notification", "error", err)
			os.Exit(1)
		}
	}
}
