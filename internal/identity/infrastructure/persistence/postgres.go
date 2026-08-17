package persistence

import (
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
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

func pgText(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{Valid: false}
	}

	return pgtype.Text{String: *s, Valid: true}
}

func fromPgText(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}

	s := t.String
	return &s
}

func pgTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func pgTimestamptzPtr(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{Valid: false}
	}

	return pgtype.Timestamptz{Time: *t, Valid: true}
}

func fromPgTimestamptz(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}

	tt := t.Time
	return &tt
}

func pgInt8(v *int64) pgtype.Int8 {
	if v == nil {
		return pgtype.Int8{Valid: false}
	}

	return pgtype.Int8{Int64: *v, Valid: true}
}

func fromPgInt8(v pgtype.Int8) *int64 {
	if !v.Valid {
		return nil
	}

	val := v.Int64
	return &val
}

func inetPtr(s *string) *netip.Addr {
	if s == nil || *s == "" {
		return nil
	}

	addr, err := netip.ParseAddr(*s)
	if err != nil {
		return nil
	}

	return &addr
}

func fromInetPtr(a *netip.Addr) *string {
	if a == nil {
		return nil
	}

	s := a.String()
	return &s
}
