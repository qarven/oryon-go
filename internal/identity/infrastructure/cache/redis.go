package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/redis/go-redis/v9"
)

// refreshTokenDenyKeyPrefix is the Redis key prefix for revoked refresh tokens.
const refreshTokenDenyKeyPrefix = "identity:refresh-token:deny:"

type Redis struct {
	conn *redis.Client
	ins  instrument.Instrumentation
}

func NewRedis(conn *redis.Client, ins instrument.Instrumentation) *Redis {
	return &Redis{
		conn: conn,
		ins:  ins,
	}
}

// RevokeRefreshToken blocks the refresh token identified by id until the ttl expires.
func (r *Redis) RevokeRefreshToken(ctx context.Context, id string, ttl time.Duration) error {
	ctx, span := r.ins.Tracer("identity.infrastructure.cache").Start(ctx, "RevokeRefreshToken")
	defer span.End()

	err := r.conn.Set(ctx, refreshTokenDenyKeyPrefix+id, "1", ttl).Err()
	if err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}

	return nil
}

// IsRefreshTokenRevoked reports whether the refresh token identified by id has been revoked.
func (r *Redis) IsRefreshTokenRevoked(ctx context.Context, id string) (bool, error) {
	ctx, span := r.ins.Tracer("identity.infrastructure.cache").Start(ctx, "IsRefreshTokenRevoked")
	defer span.End()

	n, err := r.conn.Exists(ctx, refreshTokenDenyKeyPrefix+id).Result()
	if err != nil {
		return false, fmt.Errorf("check revoked refresh token: %w", err)
	}

	return n > 0, nil
}
