package cache

import (
	"context"
	"time"
)

func (r *Redis) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	ctx, span := r.ins.Tracer("identity.cache").Start(ctx, "Set")
	defer span.End()

	return r.conn.Set(ctx, key, value, ttl).Err()
}

func (r *Redis) Get(ctx context.Context, key string) ([]byte, error) {
	ctx, span := r.ins.Tracer("identity.cache").Start(ctx, "Get")
	defer span.End()

	b, err := r.conn.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (r *Redis) Delete(ctx context.Context, key string) error {
	ctx, span := r.ins.Tracer("identity.cache").Start(ctx, "Delete")
	defer span.End()

	return r.conn.Del(ctx, key).Err()
}

func (r *Redis) Exists(ctx context.Context, key string) (bool, error) {
	ctx, span := r.ins.Tracer("identity.cache").Start(ctx, "Exists")
	defer span.End()

	n, err := r.conn.Exists(ctx, key).Result()
	return n > 0, err
}

func (r *Redis) IncrWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	ctx, span := r.ins.Tracer("identity.cache").Start(ctx, "IncrWithTTL")
	defer span.End()

	pipe := r.conn.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}

	return incr.Val(), nil
}

func (r *Redis) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	ctx, span := r.ins.Tracer("identity.cache").Start(ctx, "SetNX")
	defer span.End()

	return r.conn.SetNX(ctx, key, value, ttl).Result()
}
