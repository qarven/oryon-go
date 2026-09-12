package redis

import (
	"context"
	"time"
)

// IncrementVerificationRequest atomically increments the counter at key and
// sets its TTL only when the counter is created (fixed window).
//
// Callers build distinct keys per dimension (e.g. per email and per IP) and
// compare the returned count against their configured limit.
func (r *Redis) IncrementVerificationRequest(ctx context.Context, key string, window time.Duration) (int64, error) {
	ctx, span := r.ins.Tracer("identity.cache").Start(ctx, "IncrementVerificationRequest")
	defer span.End()

	count, err := r.conn.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	if count == 1 {
		if err := r.conn.Expire(ctx, key, window).Err(); err != nil {
			return 0, err
		}
	}

	return count, nil
}
