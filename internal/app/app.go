package app

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qarven/oryon-go/internal/pkg/clock"
	"github.com/qarven/oryon-go/internal/pkg/config"
	"github.com/qarven/oryon-go/internal/pkg/goroutine"
	"github.com/qarven/oryon-go/internal/pkg/hash"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
	"github.com/qarven/oryon-go/internal/pkg/mail"
	"github.com/qarven/oryon-go/internal/pkg/uid"
	"github.com/qarven/oryon-go/internal/pkg/validator"
	"github.com/redis/go-redis/v9"
)

// App wires dependencies and manages service lifecycle.
type App struct {
	//nolint:containedctx // App owns the root context for its whole lifecycle
	ctx    context.Context
	cancel context.CancelFunc

	// configuration
	config config.Config
	ins    instrument.Instrumentation

	// libraries
	goroutine  *goroutine.Manager
	validator  validator.Validator
	clock      clock.Clocker
	hmac       hash.Hash
	argon2id   hash.Hash
	bcrypt     hash.Hash
	uuid       uid.StringID
	uid        uid.NumberID
	accessJWT  jwt.JWT
	refreshJWT jwt.JWT

	// resources
	dbConn    *pgxpool.Pool
	cacheConn *redis.Client
	mail      mail.Mail

	// server
	connectServiceNames []string
	muxer               *http.ServeMux
	httpServer          *http.Server
	interceptors        []connect.Interceptor
	closers             []struct {
		name string
		fn   func(context.Context) error
	}
}

// New initializes the application with default wiring and returns an App instance.
func New() *App {
	ctx, cancel := context.WithCancel(context.Background())
	app := &App{
		ctx:    ctx,
		cancel: cancel,
		muxer:  http.NewServeMux(),
	}

	app.initConfig()
	app.initInstrument()
	app.initLibraries()
	app.initJWT()
	app.initDatabase()
	app.initCache()
	app.initMail()
	app.initMiddleware() // init global middleware
	app.initModules()    // init before http server
	app.initHTTPServer() // init after modules
	app.initClosers()

	return app
}
