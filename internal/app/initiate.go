package app

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"
	connectcors "connectrpc.com/cors"
	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qarven/oryon-go/internal/pkg/clock"
	"github.com/qarven/oryon-go/internal/pkg/config"
	"github.com/qarven/oryon-go/internal/pkg/goroutine"
	"github.com/qarven/oryon-go/internal/pkg/hash"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/qarven/oryon-go/internal/pkg/jwt"
	"github.com/qarven/oryon-go/internal/pkg/mail"
	"github.com/qarven/oryon-go/internal/pkg/middleware"
	"github.com/qarven/oryon-go/internal/pkg/uid"
	"github.com/qarven/oryon-go/internal/pkg/validator"
	"github.com/redis/go-redis/v9"
	"github.com/rs/cors"
)

const pingTimeout = 5 * time.Second

func (a *App) initConfig() {
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		path = "/config/config.yaml"
		if os.Getenv("LOCAL") == "true" {
			path = "./config/config.yaml"
		}
	}

	cfg, err := config.NewViper(path)
	if err != nil {
		slog.Error("failed to init config", "error", err)
		os.Exit(1)
	}

	err = os.Setenv("TZ", cfg.GetString("app.tz"))
	if err != nil {
		slog.Error("failed to set timezone", "error", err)
		os.Exit(1)
	}

	a.config = cfg
}

func (a *App) initInstrument() {
	ins, err := instrument.New(context.Background(), &instrument.Config{
		Enabled:          true,
		ServiceName:      a.config.GetString("instrument.service_name"),
		ServiceVersion:   a.config.GetString("instrument.service_version"),
		Environment:      a.config.GetString("instrument.env"),
		OTLPEndpoint:     a.config.GetString("instrument.otlp_endpoint"),
		OTLPSecure:       a.config.GetBool("instrument.otlp_secure"),
		TraceSampleRatio: a.config.GetFloat64("instrument.trace_sample_ratio"),
		MetricsInterval:  a.config.GetSecond("instrument.metric_interval_seconds"),
		MaskFields:       a.config.GetArray("instrument.log_mask_fields"),
	})
	if err != nil {
		slog.Error("failed to init instrumentation", "error", err)
		os.Exit(1)
	}

	a.ins = ins
}

func (a *App) initLibraries() {
	a.clock = clock.New()
	a.uuid = uid.NewUUID()
	a.goroutine = goroutine.NewManager(a.config.GetInt("app.server.max_goroutine"))
	a.hmac = hash.NewHMACSHA256(a.config.GetString("hash.hmac.secret"))
	a.argon2id = hash.NewArgon2id(a.config.GetString("hash.argon2id.pepper"))
	a.bcrypt = hash.NewBcrypt(a.config.GetInt("hash.bcrypt.cost"), a.config.GetString("hash.bcrypt.pepper"))

	validator, err := validator.NewV10Validator()
	if err != nil {
		slog.Error("failed to init validation v10 validator", "error", err)
		os.Exit(1)
	}

	a.validator = validator

	snow, err := uid.NewSnowflake()
	if err != nil {
		slog.Error("failed to init uid number snowflake", "error", err)
		os.Exit(1)
	}

	a.uid = snow
}

func (a *App) initJWT() {
	accessJWT, err := jwt.NewHS512(jwt.Config{
		Secret:    []byte(a.config.GetString("jwt.access.secret")),
		Issuer:    a.config.GetString("jwt.access.issuer"),
		Audiences: a.config.GetArray("jwt.access.audiences"),
		TTL:       a.config.GetMinute("jwt.access.ttl"),
		Clock:     a.clock,
	})
	if err != nil {
		slog.Error("failed to init jwt access token", "error", err)
		os.Exit(1)
	}

	refreshJWT, err := jwt.NewHS512(jwt.Config{
		Secret:    []byte(a.config.GetString("jwt.refresh.secret")),
		Issuer:    a.config.GetString("jwt.refresh.issuer"),
		Audiences: a.config.GetArray("jwt.refresh.audiences"),
		TTL:       a.config.GetDay("jwt.refresh.ttl"),
		Clock:     a.clock,
	})
	if err != nil {
		slog.Error("failed to init jwt refresh token", "error", err)
		os.Exit(1)
	}

	a.accessJWT = accessJWT
	a.refreshJWT = refreshJWT
}

func (a *App) initDatabase() {
	config, err := pgxpool.ParseConfig(a.config.GetString("database.url"))
	if err != nil {
		slog.Error("failed to parse DB connection string.", "error", err)
		os.Exit(1)
	}

	config.MaxConns = a.config.GetInt32("database.pool.max_conns")
	config.MinConns = a.config.GetInt32("database.pool.min_conns")
	config.MaxConnLifetime = a.config.GetSecond("database.pool.max_conn_lifetime_seconds")
	config.MaxConnIdleTime = a.config.GetSecond("database.pool.max_conn_idle_seconds")
	config.HealthCheckPeriod = a.config.GetSecond("database.pool.health_check_period_seconds")

	pool, err := pgxpool.NewWithConfig(a.ctx, config)
	if err != nil {
		slog.Error("failed to create DB connection pool", "error", err)
		os.Exit(1)
	}

	pingCtx, cancel := context.WithTimeout(a.ctx, pingTimeout)
	err = pool.Ping(pingCtx)

	cancel()

	if err != nil {
		slog.Error("failed to ping DB", "error", err)
		os.Exit(1)
	}

	a.dbConn = pool
}

func (a *App) initCache() {
	opt, err := redis.ParseURL(a.config.GetString("redis.url"))
	if err != nil {
		slog.Error("failed to parse redis url", "error", err)
		os.Exit(1)
	}

	rdb := redis.NewClient(opt)

	pingCtx, cancel := context.WithTimeout(a.ctx, pingTimeout)
	err = rdb.Ping(pingCtx).Err()

	cancel()

	if err != nil {
		slog.Error("failed to init redis", "error", err)
		os.Exit(1)
	}

	a.cacheConn = rdb
}

func (a *App) initMail() {
	mail, err := mail.NewSMTP(mail.SMTPConfig{
		Host:     a.config.GetString("mail.host"),
		Port:     a.config.GetInt("mail.port"),
		Username: a.config.GetString("mail.username"),
		Password: a.config.GetString("mail.password"),
		From:     a.config.GetString("mail.from"),
	})
	if err != nil {
		slog.Error("failed to init mail", "error", err)
		os.Exit(1)
	}

	a.mail = mail
}

func (a *App) initMiddleware() {
a.interceptors = []connect.Interceptor{
		middleware.NewRecoveryInterceptor(),
		middleware.NewMaintenanceInterceptor(a.config.GetArray("app.maintenance.endpoints")),
		middleware.NewObservabilityInterceptor(), // outermost: sets the chain ID and logs every request
		middleware.NewErrorInterceptor(),
		middleware.NewAuthenticationInterceptor(a.accessJWT, a.config.GetArray("app.authentication.public_endpoints")),
	}
}

func (a *App) initHTTPServer() {
	if a.config.GetBool("connect.with.reflection") {
		reflector := grpcreflect.NewStaticReflector(a.connectServiceNames...)
		a.muxer.Handle(grpcreflect.NewHandlerV1(reflector))
		a.muxer.Handle(grpcreflect.NewHandlerV1Alpha(reflector))
	}

	if a.config.GetBool("connect.with.healthcheck") {
		checker := grpchealth.NewStaticChecker(a.connectServiceNames...)
		a.muxer.Handle(grpchealth.NewHandler(checker))
	}

	corsHandler := cors.New(cors.Options{ //nolint:exhaustruct // only origins, methods and headers are customized
		AllowedOrigins: a.config.GetArray("app.server.cors"),
		AllowedMethods: connectcors.AllowedMethods(),
		AllowedHeaders: append(connectcors.AllowedHeaders(), "Authorization"),
		ExposedHeaders: connectcors.ExposedHeaders(),
	})

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	a.httpServer = &http.Server{ //nolint:exhaustruct // only address, timeouts and handler are configured
		Addr:              a.config.GetString("app.server.http.address"),
		Handler:           corsHandler.Handler(a.muxer),
		ReadTimeout:       a.config.GetSecond("app.server.http.read_timeout_seconds"),
		ReadHeaderTimeout: a.config.GetSecond("app.server.http.read_header_timeout_seconds"),
		WriteTimeout:      a.config.GetSecond("app.server.http.write_timeout_seconds"),
		IdleTimeout:       a.config.GetSecond("app.server.http.idle_timeout_seconds"),
		Protocols:         protocols,
	}
}

func (a *App) initClosers() {
	a.closers = []struct {
		name string
		fn   func(context.Context) error
	}{
		{
			name: "Instrument",
			fn: func(ctx context.Context) error {
				return a.ins.Shutdown(ctx)
			},
		},
		{
			name: "Redis",
			fn: func(context.Context) error {
				return a.cacheConn.Close()
			},
		},
		{
			name: "Database",
			fn: func(context.Context) error {
				a.dbConn.Close()

				return nil
			},
		},
		{
			name: "Config",
			fn: func(context.Context) error {
				return a.config.Close()
			},
		},
	}
}
