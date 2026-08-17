package cache

import (
	"context"
	"fmt"
	"time"
)

const (
	VerificationAttemptPrefix = "verification:attempt:"
	VerificationAttemptTTL    = 15 * time.Minute
	VerificationAttemptLimit  = 5
)

func verificationAttemptKey(identifier string) string {
	return fmt.Sprintf("%s%s", VerificationAttemptPrefix, identifier)
}

func (r *Redis) CheckVerificationRateLimit(ctx context.Context, identifier string) (bool, error) {
	ctx, span := r.ins.Tracer("identity.cache").Start(ctx, "CheckVerificationRateLimit")
	defer span.End()

	key := verificationAttemptKey(identifier)
	cnt, err := r.conn.Get(ctx, key).Int()
	if err != nil {
		// key not exists
		return true, nil
	}

	return cnt < VerificationAttemptLimit, nil
}

func (r *Redis) IncrementVerificationAttempt(ctx context.Context, identifier string) error {
	ctx, span := r.ins.Tracer("identity.cache").Start(ctx, "IncrementVerificationAttempt")
	defer span.End()

	key := verificationAttemptKey(identifier)
	pipe := r.conn.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, VerificationAttemptTTL)

	_, err := pipe.Exec(ctx)
	return err
}

func (r *Redis) ResetVerificationAttempts(ctx context.Context, identifier string) error {
	ctx, span := r.ins.Tracer("identity.cache").Start(ctx, "ResetVerificationAttempts")
	defer span.End()

	return r.conn.Del(ctx, verificationAttemptKey(identifier)).Err()
}
