package persistence

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

type Postgres struct {
	conn  *pgxpool.Pool
	query *sqlc.Queries
	ins   instrument.Instrumentation
}

func NewPostgres(conn *pgxpool.Pool, ins instrument.Instrumentation) *Postgres {
	return &Postgres{
		conn:  conn,
		query: sqlc.New(conn),
		ins:   ins,
	}
}
