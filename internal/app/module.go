package app

import (
	"log/slog"
	"os"

	"github.com/qarven/oryon-go/internal/identity"
)

func (a *App) initModules() {
	if a.config.GetBool("modules.identity.enabled") {
		serviceNames, err := identity.New(identity.Dependency{
			Config:       a.config,
			Instrument:   a.ins,
			UID:          a.uid,
			UUID:         a.uuid,
			Argon2ID:     a.argon2id,
			Clock:        a.clock,
			Validator:    a.validator,
			DBConn:       a.dbConn,
			CacheConn:    a.cacheConn,
			Goroutine:    a.goroutine,
			Interceptors: a.interceptors,
			Muxer:        a.muxer,
		})
		if err != nil {
			slog.Error("failed to init module identity", "error", err)
			os.Exit(1)
		}

		a.connectServiceNames = append(a.connectServiceNames, serviceNames...)
	}
}
