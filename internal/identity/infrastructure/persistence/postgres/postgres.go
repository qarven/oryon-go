package postgres

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qarven/oryon-go/internal/identity/domain"
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/qarven/oryon-go/internal/pkg/sqlc"
)

type Postgres struct {
	conn  *pgxpool.Pool
	query *sqlc.Queries
	ins   instrument.Instrumentation
}

func New(conn *pgxpool.Pool, ins instrument.Instrumentation) *Postgres {
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

func pgTz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func pgTzPtr(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{Valid: false}
	}

	return pgtype.Timestamptz{Time: *t, Valid: true}
}

func fromPgTz(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}

	tt := t.Time

	return &tt
}

func pgUUID(id domain.ID) pgtype.UUID {
	var pguuid pgtype.UUID

	err := pguuid.Scan(id.String())
	if err != nil {
		return pgtype.UUID{Valid: false}
	}

	return pguuid
}

func pgUUIDPtr(id *domain.ID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{Valid: false}
	}

	return pgUUID(*id)
}

func fromPgUUID(u pgtype.UUID) domain.ID {
	if !u.Valid {
		return ""
	}

	return domain.IDFrom(uuid.UUID(u.Bytes).String())
}

func fromPgUUIDPtr(u pgtype.UUID) *domain.ID {
	if !u.Valid {
		return nil
	}

	id := fromPgUUID(u)

	return &id
}
