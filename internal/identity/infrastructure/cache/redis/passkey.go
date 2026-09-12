package redis

// import (
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"time"

// 	"github.com/qarven/oryon-go/internal/identity/domain"
// )

// const (
// 	PasskeyChallengePrefix = "passkey:challenge:"
// 	PasskeyChallengeTTL    = 5 * time.Minute
// )

// func passkeyChallengeKey(flowID int64) string {
// 	return fmt.Sprintf("%s%d", PasskeyChallengePrefix, flowID)
// }

// func (r *Redis) StorePasskeyChallenge(ctx context.Context, ch domain.PasskeyChallenge) error {
// 	ctx, span := r.ins.Tracer("identity.cache").Start(ctx, "StorePasskeyChallenge")
// 	defer span.End()

// 	b, err := json.Marshal(ch)
// 	if err != nil {
// 		return err
// 	}

// 	return r.conn.Set(ctx, passkeyChallengeKey(ch.FlowID), b, PasskeyChallengeTTL).Err()
// }

// func (r *Redis) GetPasskeyChallenge(ctx context.Context, flowID int64) (*domain.PasskeyChallenge, error) {
// 	ctx, span := r.ins.Tracer("identity.cache").Start(ctx, "GetPasskeyChallenge")
// 	defer span.End()

// 	b, err := r.conn.Get(ctx, passkeyChallengeKey(flowID)).Bytes()
// 	if err != nil {
// 		return nil, err
// 	}

// 	var ch domain.PasskeyChallenge
// 	if err := json.Unmarshal(b, &ch); err != nil {
// 		return nil, err
// 	}

// 	return &ch, nil
// }

// func (r *Redis) DeletePasskeyChallenge(ctx context.Context, flowID int64) error {
// 	ctx, span := r.ins.Tracer("identity.cache").Start(ctx, "DeletePasskeyChallenge")
// 	defer span.End()

// 	return r.conn.Del(ctx, passkeyChallengeKey(flowID)).Err()
// }
