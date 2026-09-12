package postgres

// import (
// 	"context"
// 	"errors"

// 	"github.com/jackc/pgx/v5"
// 	"github.com/jackc/pgx/v5/pgtype"
// 	"github.com/qarven/oryon-go/internal/identity/domain"
// 	"github.com/qarven/oryon-go/internal/pkg/sqlc"
// )

// func (p *Postgres) CreateUser(ctx context.Context, user domain.User) error {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "CreateUser")
// 	defer span.End()

// 	return p.query.CreateUser(ctx, sqlc.CreateUserParams{
// 		ID:        user.ID,
// 		Status:    int16(user.Status),
// 		Name:      user.Name,
// 		AvatarUrl: pgText(user.AvatarURL),
// 		CreatedAt: pgTz(user.CreatedAt),
// 		UpdatedAt: pgTz(user.UpdatedAt),
// 		DeletedAt: pgTzPtr(user.DeletedAt),
// 	})
// }

// func (p *Postgres) UpdateUser(ctx context.Context, user domain.User) error {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "UpdateUser")
// 	defer span.End()

// 	err := p.query.UpdateUser(ctx, sqlc.UpdateUserParams{
// 		ID:        user.ID,
// 		Status:    int16(user.Status),
// 		Name:      user.Name,
// 		AvatarUrl: pgText(user.AvatarURL),
// 		UpdatedAt: pgTz(user.UpdatedAt),
// 		DeletedAt: pgTzPtr(user.DeletedAt),
// 	})
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

// func (p *Postgres) ListUsers(ctx context.Context, limit, offset int32) ([]domain.User, int64, error) {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "ListUsers")
// 	defer span.End()

// 	// Not using sqlc for pagination with count; keep manual for now or use simple query
// 	// Fallback to manual query
// 	q := `SELECT id, status, name, avatar_url, created_at, updated_at, deleted_at, COUNT(*) OVER() FROM users ORDER BY id LIMIT $1 OFFSET $2`
// 	rows, err := p.conn.Query(ctx, q, limit, offset)
// 	if err != nil {
// 		return nil, 0, err
// 	}
// 	defer rows.Close()

// 	var users []domain.User
// 	var total int64
// 	for rows.Next() {
// 		var u domain.User
// 		var avatar pgtype.Text
// 		var deleted pgtype.Timestamptz
// 		var created pgtype.Timestamptz
// 		var updated pgtype.Timestamptz
// 		if err := rows.Scan(&u.ID, &u.Status, &u.Name, &avatar, &created, &updated, &deleted, &total); err != nil {
// 			return nil, 0, err
// 		}
// 		u.AvatarURL = fromPgText(avatar)
// 		u.CreatedAt = created.Time
// 		u.UpdatedAt = updated.Time
// 		u.DeletedAt = fromPgTz(deleted)
// 		users = append(users, u)
// 	}
// 	if err := rows.Err(); err != nil {
// 		return nil, 0, err
// 	}
// 	return users, total, nil
// }

// // Legacy compat
// func (p *Postgres) GetIdentityByEmail(ctx context.Context, email string) (domain.Identity, error) {
// 	ctx, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetIdentityByEmail")
// 	defer span.End()

// 	userEmail, err := p.GetUserEmailByEmail(ctx, email)
// 	if err != nil {
// 		return domain.Identity{}, err
// 	}
// 	user, err := p.GetUserByID(ctx, userEmail.UserID)
// 	if err != nil {
// 		return domain.Identity{}, err
// 	}
// 	return domain.Identity{
// 		ID:        user.ID,
// 		UserID:    user.ID,
// 		CreatedAt: user.CreatedAt,
// 	}, nil
// }

// func (p *Postgres) GetIdentityByID(ctx context.Context, id int64) (domain.Identity, error) {
// 	_, span := p.ins.Tracer("identity.persistence").Start(ctx, "GetIdentityByID")
// 	defer span.End()
// 	u, err := p.GetUserByID(ctx, id)
// 	if err != nil {
// 		return domain.Identity{}, err
// 	}
// 	return domain.Identity{
// 		ID:        u.ID,
// 		UserID:    u.ID,
// 		CreatedAt: u.CreatedAt,
// 	}, nil
// }
