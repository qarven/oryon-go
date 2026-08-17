package cache

import (
	"github.com/qarven/oryon-go/internal/pkg/instrument"
	"github.com/redis/go-redis/v9"
)

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
